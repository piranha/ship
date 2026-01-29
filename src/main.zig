const std = @import("std");
const build_options = @import("build_options");
const opt = @import("opt");

const CompressMode = enum { auto, on, off };

const Options = struct {
    jobs: u32 = 8,
    ssh: []const u8 = "ssh",
    ssh_opts: []const u8 = "-oBatchMode=yes -oConnectTimeout=5",
    port: ?u16 = null,
    user: ?[]const u8 = null,
    skip_md5: bool = false,
    compress: CompressMode = .auto,
    compress_level: u4 = 1,
    chmod: ?u16 = 0o755,
    tmp: ?[]const u8 = null,
    sudo: bool = false,
    sudo_cmd: []const u8 = "sudo -n",
    install_owner: ?[]const u8 = null,
    timeout: ?u32 = null,
    stall_timeout: u32 = 10,
    quiet: bool = false,
    keep_tmp_on_fail: bool = false,
    restart: ?[]const u8 = null,
    version: bool = false,

    pub const meta = .{
        .jobs = .{ .short = 'j', .help = "Max parallel hosts" },
        .ssh = .{ .help = "SSH binary" },
        .ssh_opts = .{ .help = "SSH options" },
        .port = .{ .help = "Default SSH port" },
        .user = .{ .help = "Default SSH user" },
        .skip_md5 = .{ .help = "Skip remote MD5 check" },
        .compress = .{ .flag_value = .on, .no_value = .off, .help = "Compression mode" },
        .compress_level = .{ .help = "Gzip level 1-9" },
        .chmod = .{
            .help = "File mode in octal (default: 755, --no-chmod to skip)",
            .parse = struct {
                fn p(val: []const u8) ?u16 {
                    return std.fmt.parseInt(u16, val, 8) catch null;
                }
            }.p,
        },
        .tmp = .{ .help = "Exact temp path (skip auto-detection)" },
        .sudo = .{ .help = "Use sudo for install" },
        .sudo_cmd = .{ .help = "Sudo command" },
        .install_owner = .{ .help = "Set owner:group via sudo" },
        .timeout = .{ .help = "SSH timeout in seconds" },
        .stall_timeout = .{ .help = "Stall timeout in seconds" },
        .quiet = .{ .short = 'q', .help = "No progress output" },
        .keep_tmp_on_fail = .{ .help = "Keep temp file on failure" },
        .restart = .{ .help = "Command to run after install" },
        .version = .{ .short = 'V', .help = "Show version" },
    };

    pub const about = .{
        .name = "ship",
        .desc = "Upload a file to multiple hosts in parallel",
        .usage =
        \\Usage: ship [options] <local_path:remote_dest> <host...>
        \\
        \\Host format: [user@]host[:dest]
        \\  so you can override user and destination per-host
        \\
        ,
    };
};

const Config = struct {
    local_path: []const u8,
    default_dest: []const u8,
    hosts: []HostSpec,
    opts: Options,
};

const HostSpec = struct {
    host: []const u8,
    user: ?[]const u8,
    dest: ?[]const u8,
};

const HostStatus = enum {
    pending,
    checking,
    uploading,
    installing,
    restarting,
    done,
    skipped,
    failed,
};

const HostState = struct {
    spec: HostSpec,
    status: HostStatus,
    progress: u8, // 0-100
    bytes_sent: u64, // for speed calc
    start_time: std.time.Instant, // for speed calc
    last_progress_time: std.time.Instant, // for stall detection
    error_msg: ?[]const u8,
    child_pid: ?std.posix.pid_t, // for killing on stall
    gzip_pid: ?std.posix.pid_t, // for killing on stall (compression)
};

fn parseHostSpec(spec: []const u8) HostSpec {
    // split at last ':'
    var last_colon: ?usize = null;
    for (spec, 0..) |c, i| {
        if (c == ':') last_colon = i;
    }

    var host_part = spec;
    var dest: ?[]const u8 = null;
    if (last_colon) |idx| {
        dest = spec[idx + 1 ..];
        host_part = spec[0..idx];
    }

    // split user@host
    var user: ?[]const u8 = null;
    var host: []const u8 = host_part;
    if (std.mem.indexOf(u8, host_part, "@")) |at_idx| {
        user = host_part[0..at_idx];
        host = host_part[at_idx + 1 ..];
    }

    return .{ .host = host, .user = user, .dest = dest };
}

fn printUsage() void {
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buf);
    opt.printUsage(Options, &stdout.interface);
    stdout.interface.flush() catch {};
}

fn parseArgs(allocator: std.mem.Allocator) !?Config {
    // NOTE: don't free args - strings are borrowed into Config
    const args = try std.process.argsAlloc(allocator);

    var opts = Options{};
    const positionals = opt.parse(Options, &opts, args[1..]) catch |e| {
        if (e == error.Help) {
            printUsage();
            return null;
        }
        std.debug.print("Error parsing arguments: {s}\n", .{@errorName(e)});
        return error.InvalidArgument;
    };

    if (opts.version) {
        var buf: [64]u8 = undefined;
        var stdout = std.fs.File.stdout().writer(&buf);
        stdout.interface.print("ship {s}\n", .{build_options.version}) catch {};
        stdout.interface.flush() catch {};
        return null;
    }
    if (positionals.len < 2) {
        printUsage();
        return null;
    }

    // first positional: local_path:remote_dest
    const first = positionals[0];
    const colon_idx = std.mem.indexOf(u8, first, ":") orelse {
        std.debug.print("First argument must be local_path:remote_dest\n", .{});
        return error.InvalidArgument;
    };
    const local_path = first[0..colon_idx];
    const default_dest = first[colon_idx + 1 ..];

    // remaining positionals: hosts
    var hosts: std.ArrayList(HostSpec) = .{};
    errdefer hosts.deinit(allocator);
    for (positionals[1..]) |arg| {
        try hosts.append(allocator, parseHostSpec(arg));
    }

    if (opts.jobs > hosts.items.len) opts.jobs = @intCast(hosts.items.len);

    return .{
        .local_path = local_path,
        .default_dest = default_dest,
        .hosts = try hosts.toOwnedSlice(allocator),
        .opts = opts,
    };
}

fn escapeShellArg(allocator: std.mem.Allocator, arg: []const u8) ![]const u8 {
    // single-quote escape: replace ' with '\''
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);
    try result.append(allocator, '\'');
    for (arg) |c| {
        if (c == '\'') {
            try result.appendSlice(allocator, "'\\''");
        } else {
            try result.append(allocator, c);
        }
    }
    try result.append(allocator, '\'');
    return result.toOwnedSlice(allocator);
}

fn escapeRemotePath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, path, "~/")) {
        const rest = path[2..];
        const escaped_rest = try escapeShellArg(allocator, rest);
        defer allocator.free(escaped_rest);
        return std.fmt.allocPrint(allocator, "\"$HOME\"/{s}", .{escaped_rest});
    }
    return escapeShellArg(allocator, path);
}

fn computeLocalMd5(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.Md5.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var digest: [16]u8 = undefined;
    hasher.final(&digest);
    const hex_arr = std.fmt.bytesToHex(&digest, .lower);
    const hex = try allocator.alloc(u8, 32);
    @memcpy(hex, &hex_arr);
    return hex;
}

const Ship = struct {
    allocator: std.mem.Allocator,
    config: Config,
    states: []HostState,
    local_md5: []const u8,
    local_size: u64,
    mutex: std.Thread.Mutex,
    failed_count: u32,
    use_compression: bool,
    output_tty: bool,

    fn init(allocator: std.mem.Allocator, config: Config) !*Ship {
        const ship = try allocator.create(Ship);
        ship.* = .{
            .allocator = allocator,
            .config = config,
            .states = try allocator.alloc(HostState, config.hosts.len),
            .local_md5 = undefined,
            .local_size = undefined,
            .mutex = .{},
            .failed_count = 0,
            .use_compression = false,
            .output_tty = false,
        };
        const now = std.time.Instant.now() catch @panic("no clock");
        for (config.hosts, 0..) |host, i| {
            ship.states[i] = .{
                .spec = host,
                .status = .pending,
                .progress = 0,
                .bytes_sent = 0,
                .start_time = now,
                .last_progress_time = now,
                .error_msg = null,
                .child_pid = null,
                .gzip_pid = null,
            };
        }
        return ship;
    }

    fn deinit(self: *Ship) void {
        self.allocator.free(self.local_md5);
        self.allocator.free(self.states);
        self.allocator.free(self.config.hosts);
        self.allocator.destroy(self);
    }

    fn run(self: *Ship) !u8 {
        // compute local md5
        self.local_md5 = try computeLocalMd5(self.allocator, self.config.local_path);

        // get local file size
        const stat = try std.fs.cwd().statFile(self.config.local_path);
        self.local_size = stat.size;

        // determine compression
        self.use_compression = switch (self.config.opts.compress) {
            .on => true,
            .off => false,
            .auto => self.local_size >= 512 * 1024,
        };

        self.output_tty = std.fs.File.stdout().isTty();

        // spawn workers
        var threads = try self.allocator.alloc(std.Thread, self.config.opts.jobs);
        var next_host: u32 = 0;

        for (0..self.config.opts.jobs) |i| {
            threads[i] = try std.Thread.spawn(.{}, workerThread, .{ self, &next_host });
        }

        // progress display loop
        if (!self.config.opts.quiet) {
            try self.progressLoop(threads);
        }

        for (threads) |t| t.join();
        self.allocator.free(threads);

        // final status line
        if (!self.config.opts.quiet) {
            try self.printFinalStatus();
        }

        return if (self.failed_count > 0) 1 else 0;
    }

    fn workerThread(self: *Ship, next_host: *u32) void {
        while (true) {
            var idx: u32 = undefined;
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (next_host.* >= self.config.hosts.len) return;
                idx = next_host.*;
                next_host.* += 1;
            }
            self.processHost(idx) catch |err| {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.states[idx].error_msg == null)
                    self.states[idx].error_msg = @errorName(err);
                self.setStatusLocked(idx, .failed);
            };
        }
    }

    fn processHost(self: *Ship, idx: u32) !void {
        const state = &self.states[idx];
        const spec = state.spec;
        const dest = spec.dest orelse self.config.default_dest;

        // probe remote: md5 check + fs info in single ssh call
        self.setStatus(idx, .checking);
        const probe = try self.probeRemote(spec, dest);

        // skip if md5 matches
        if (!self.config.opts.skip_md5) {
            if (probe.md5) |md5| {
                if (std.mem.eql(u8, &md5, self.local_md5)) {
                    self.setStatus(idx, .skipped);
                    return;
                }
            }
        }

        // upload
        self.setStatus(idx, .uploading);
        const tmp_path = try self.getTmpPath(probe.fs_info, dest);
        defer self.allocator.free(tmp_path);
        try self.uploadFile(idx, spec, tmp_path, probe.has_gunzip);

        // install
        self.setStatus(idx, .installing);
        try self.installFile(idx, spec, tmp_path, dest);

        // restart
        if (self.config.opts.restart) |cmd| {
            self.setStatus(idx, .restarting);
            try self.runRestart(spec, cmd);
        }

        self.setStatus(idx, .done);
    }

    fn setStatus(self: *Ship, idx: u32, status: HostStatus) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.setStatusLocked(idx, status);
    }

    fn setStatusLocked(self: *Ship, idx: u32, status: HostStatus) void {
        const prev = self.states[idx].status;
        self.states[idx].status = status;
        if (status == .failed and prev != .failed) self.failed_count += 1;
        if (status == .uploading) {
            const now = std.time.Instant.now() catch return;
            self.states[idx].start_time = now;
            self.states[idx].last_progress_time = now;
        }
        self.logFinalLocked(idx, prev);
    }

    fn logFinalLocked(self: *Ship, idx: u32, prev: HostStatus) void {
        if (self.output_tty or self.config.opts.quiet) return;
        const status = self.states[idx].status;
        const was_terminal = prev == .done or prev == .skipped or prev == .failed;
        const is_terminal = status == .done or status == .skipped or status == .failed;
        if (!is_terminal or was_terminal) return;
        const label = self.getHostLabel(self.states[idx].spec);
        const stdout = std.fs.File.stdout();
        var buf: [512]u8 = undefined;
        const line = switch (status) {
            .done => std.fmt.bufPrint(&buf, "{s} OK\n", .{label}) catch return,
            .skipped => std.fmt.bufPrint(&buf, "{s} SKIP\n", .{label}) catch return,
            .failed => blk: {
                const msg = self.states[idx].error_msg orelse "unknown";
                break :blk std.fmt.bufPrint(&buf, "{s} ERR {s}\n", .{ label, msg }) catch return;
            },
            else => return,
        };
        stdout.writeAll(line) catch {};
    }

    fn setProgress(self: *Ship, idx: u32, progress: u8, bytes_sent: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const old_progress = self.states[idx].progress;
        self.states[idx].progress = progress;
        self.states[idx].bytes_sent = bytes_sent;
        if (progress != old_progress) {
            const now = std.time.Instant.now() catch return;
            self.states[idx].last_progress_time = now;
        }
    }

    fn setErrorMsg(self: *Ship, idx: u32, msg: []const u8) bool {
        if (msg.len == 0) return false;
        if (self.allocator.dupe(u8, msg)) |dup| {
            self.mutex.lock();
            if (self.states[idx].error_msg == null) {
                self.states[idx].error_msg = dup;
                self.mutex.unlock();
                return true;
            }
            self.mutex.unlock();
            self.allocator.free(dup);
        } else |_| {}
        return false;
    }

    const SshArgs = struct {
        args: std.ArrayList([]const u8),
        port_str: ?[]const u8,
        timeout_str: ?[]const u8,
        allocator: std.mem.Allocator,

        fn deinit(self: *SshArgs) void {
            if (self.port_str) |p| self.allocator.free(p);
            if (self.timeout_str) |t| self.allocator.free(t);
            self.args.deinit(self.allocator);
        }
    };

    fn buildSshArgs(self: *Ship, spec: HostSpec) !SshArgs {
        var result = SshArgs{
            .args = .{},
            .port_str = null,
            .timeout_str = null,
            .allocator = self.allocator,
        };
        errdefer result.deinit();

        try result.args.append(self.allocator, self.config.opts.ssh);

        // parse and add ssh_opts
        var it = std.mem.splitScalar(u8, self.config.opts.ssh_opts, ' ');
        while (it.next()) |o| {
            if (o.len > 0) try result.args.append(self.allocator, o);
        }

        // Add timeout via SSH options (ServerAliveInterval=timeout, ServerAliveCountMax=1)
        const timeout = self.config.opts.timeout orelse 30; // default 30s
        result.timeout_str = try std.fmt.allocPrint(self.allocator, "-oServerAliveInterval={d}", .{timeout});
        try result.args.append(self.allocator, result.timeout_str.?);
        try result.args.append(self.allocator, "-oServerAliveCountMax=1");

        if (self.config.opts.port) |port| {
            try result.args.append(self.allocator, "-p");
            result.port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{port});
            try result.args.append(self.allocator, result.port_str.?);
        }

        const user = spec.user orelse self.config.opts.user;
        if (user) |u| {
            try result.args.append(self.allocator, "-l");
            try result.args.append(self.allocator, u);
        }

        try result.args.append(self.allocator, spec.host);
        return result;
    }

    const FsInfo = struct {
        dest_dir: []const u8,
        dest_dev: []const u8,
        dest_free: u64,
        dest_writable: bool,
        home_dev: []const u8,
        home_free: u64,
        tmp_dev: []const u8,
        tmp_free: u64,
    };

    const ProbeResult = struct {
        md5: ?[32]u8,
        fs_info: FsInfo,
        has_gunzip: bool,
    };

    fn probeRemote(self: *Ship, spec: HostSpec, dest: []const u8) !ProbeResult {
        const escaped_dest = try escapeShellArg(self.allocator, dest);
        defer self.allocator.free(escaped_dest);

        const dest_dir = std.fs.path.dirname(dest) orelse "/";
        const escaped_dest_dir = try escapeShellArg(self.allocator, dest_dir);
        defer self.allocator.free(escaped_dest_dir);

        const sudo_prefix = if (self.config.opts.sudo) self.config.opts.sudo_cmd else "";
        const space = if (self.config.opts.sudo) " " else "";

        // single ssh call: md5 + fs probe + gunzip check
        var cmd_buf: [2048]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf,
            \\m=$({s}{s}md5sum {s} 2>/dev/null || {s}{s}busybox md5sum {s} 2>/dev/null)
            \\d={s}
            \\dd=$(stat -c %d "$d" 2>/dev/null)
            \\df=$(($(df -k "$d" 2>/dev/null | awk 'NR==2{{print $4}}')*1024))
            \\dw=$(test -w "$d" && echo 1 || echo 0)
            \\hd=$(stat -c %d ~ 2>/dev/null)
            \\hf=$(($(df -k ~ 2>/dev/null | awk 'NR==2{{print $4}}')*1024))
            \\td=$(stat -c %d /tmp 2>/dev/null)
            \\tf=$(($(df -k /tmp 2>/dev/null | awk 'NR==2{{print $4}}')*1024))
            \\gz=$(command -v gunzip >/dev/null 2>&1 || command -v busybox >/dev/null 2>&1 && echo 1 || echo 0)
            \\echo "$m"
            \\echo "$dd $df $dw $hd $hf $td $tf $gz"
        , .{ sudo_prefix, space, escaped_dest, sudo_prefix, space, escaped_dest, escaped_dest_dir }) catch
            return error.CommandTooLong;

        const result = try self.runSshCommand(spec, cmd);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        // parse output: first line is md5 (or empty), second line is fs info
        var lines = std.mem.splitScalar(u8, std.mem.trimRight(u8, result.stdout, "\n"), '\n');
        const md5_line = lines.next() orelse "";
        const fs_line = lines.next() orelse "";

        // parse md5 (first 32 chars if present)
        const md5: ?[32]u8 = if (md5_line.len >= 32) blk: {
            var md5: [32]u8 = undefined;
            @memcpy(&md5, md5_line[0..32]);
            break :blk md5;
        } else null;

        // parse fs info
        var it = std.mem.splitScalar(u8, fs_line, ' ');
        const fs_info = FsInfo{
            .dest_dir = dest_dir,
            .dest_dev = it.next() orelse "",
            .dest_free = std.fmt.parseInt(u64, it.next() orelse "0", 10) catch 0,
            .dest_writable = std.mem.eql(u8, it.next() orelse "0", "1"),
            .home_dev = it.next() orelse "",
            .home_free = std.fmt.parseInt(u64, it.next() orelse "0", 10) catch 0,
            .tmp_dev = it.next() orelse "",
            .tmp_free = std.fmt.parseInt(u64, it.next() orelse "0", 10) catch 0,
        };
        const has_gunzip = std.mem.eql(u8, it.next() orelse "0", "1");

        return .{ .md5 = md5, .fs_info = fs_info, .has_gunzip = has_gunzip };
    }

    fn runSshCommand(self: *Ship, spec: HostSpec, remote_cmd: []const u8) !std.process.Child.RunResult {
        var ssh_args = try self.buildSshArgs(spec);
        defer ssh_args.deinit();
        try ssh_args.args.append(self.allocator, remote_cmd);

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = ssh_args.args.items,
        });
        return result;
    }

    fn getTmpPath(self: *Ship, fs_info: FsInfo, dest: []const u8) ![]const u8 {
        // if --tmp explicitly set, use it directly (exact path, no checks)
        if (self.config.opts.tmp) |p| {
            return self.allocator.dupe(u8, p);
        }

        const basename = std.fs.path.basename(self.config.local_path);
        const pid = std.os.linux.getpid();

        // build temp filename
        var tmp_name_buf: [256]u8 = undefined;
        const tmp_name = std.fmt.bufPrint(&tmp_name_buf, ".ship.{s}.{d}.tmp", .{ basename, pid }) catch
            return error.TmpPathTooLong;

        const size_needed = self.local_size + 1024 * 1024; // 1MB margin
        const dest_dir = std.fs.path.dirname(dest) orelse "/";

        // pick best location: dest dir > home > /tmp
        const tmp_dir: []const u8 = blk: {
            if (fs_info.dest_writable and fs_info.dest_free >= size_needed) {
                break :blk dest_dir;
            }
            if (std.mem.eql(u8, fs_info.home_dev, fs_info.dest_dev) and fs_info.home_free >= size_needed) {
                break :blk "~";
            }
            if (std.mem.eql(u8, fs_info.tmp_dev, fs_info.dest_dev) and fs_info.tmp_free >= size_needed) {
                break :blk "/tmp";
            }
            // fallback: prefer same-fs even without dest write permission (sudo will handle)
            if (std.mem.eql(u8, fs_info.home_dev, fs_info.dest_dev) and fs_info.home_free >= size_needed) {
                break :blk "~";
            }
            if (std.mem.eql(u8, fs_info.tmp_dev, fs_info.dest_dev) and fs_info.tmp_free >= size_needed) {
                break :blk "/tmp";
            }
            // last resort: any location with space (mv will copy across fs)
            if (fs_info.dest_writable and fs_info.dest_free >= size_needed) break :blk dest_dir;
            if (fs_info.home_free >= size_needed) break :blk "~";
            if (fs_info.tmp_free >= size_needed) break :blk "/tmp";
            return error.NoSpaceOnRemote;
        };

        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ tmp_dir, tmp_name });
    }

    fn uploadFile(self: *Ship, idx: u32, spec: HostSpec, tmp_path: []const u8, has_gunzip: bool) !void {
        const escaped_tmp = try escapeRemotePath(self.allocator, tmp_path);
        defer self.allocator.free(escaped_tmp);

        // determine if we should compress
        var actually_compress = self.use_compression;
        if (self.config.opts.compress == .auto and self.use_compression and !has_gunzip) {
            actually_compress = false;
        }

        const remote_cmd = if (actually_compress)
            try std.fmt.allocPrint(self.allocator, "gunzip > {s} || busybox gunzip > {s}", .{ escaped_tmp, escaped_tmp })
        else
            try std.fmt.allocPrint(self.allocator, "cat > {s}", .{escaped_tmp});
        defer self.allocator.free(remote_cmd);

        var ssh_args = try self.buildSshArgs(spec);
        defer ssh_args.deinit();
        try ssh_args.args.append(self.allocator, remote_cmd);

        var child = std.process.Child.init(ssh_args.args.items, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();

        // store pid for stall detection kill
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.states[idx].child_pid = child.id;
        }
        defer {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.states[idx].child_pid = null;
        }

        // open local file and stream to ssh stdin
        const local_file = try std.fs.cwd().openFile(self.config.local_path, .{});
        defer local_file.close();

        const stdin = child.stdin.?;

        if (actually_compress) {
            // Use gzip command instead of library for now
            try self.streamWithGzip(idx, local_file, stdin);
        } else {
            try self.streamWithProgress(idx, local_file, stdin);
        }
        // Close stdin to signal EOF, then null out to prevent double-close in wait()
        stdin.close();
        child.stdin = null;

        var stdout_list: std.ArrayList(u8) = .{};
        defer stdout_list.deinit(self.allocator);
        var stderr_list: std.ArrayList(u8) = .{};
        defer stderr_list.deinit(self.allocator);
        _ = child.collectOutput(self.allocator, &stdout_list, &stderr_list, 64 * 1024) catch {};

        const term = try child.wait();
        const failed = switch (term) {
            .Exited => |code| code != 0,
            else => true,
        };
        if (failed) {
            var got_msg = false;
            const stderr_buf = stderr_list.items;
            if (stderr_buf.len > 0) {
                const first_line = if (std.mem.indexOf(u8, stderr_buf, "\n")) |nl|
                    stderr_buf[0..nl]
                else
                    stderr_buf;
                if (first_line.len > 0) {
                    got_msg = self.setErrorMsg(idx, first_line);
                }
            }
            if (!got_msg) {
                const stdout_buf = stdout_list.items;
                if (stdout_buf.len > 0) {
                    const first_line = if (std.mem.indexOf(u8, stdout_buf, "\n")) |nl|
                        stdout_buf[0..nl]
                    else
                        stdout_buf;
                    if (first_line.len > 0) {
                        got_msg = self.setErrorMsg(idx, first_line);
                    }
                }
            }
            if (!got_msg) {
                const fallback = switch (term) {
                    .Exited => |code| std.fmt.allocPrint(self.allocator, "upload failed (exit {d})", .{code}) catch null,
                    .Signal => |sig| std.fmt.allocPrint(self.allocator, "upload failed (signal {d})", .{sig}) catch null,
                    else => std.fmt.allocPrint(self.allocator, "upload failed", .{}) catch null,
                };
                if (fallback) |msg| {
                    _ = self.setErrorMsg(idx, msg);
                    self.allocator.free(msg);
                }
            }
            return error.UploadFailed;
        }
    }

    fn streamWithProgress(self: *Ship, idx: u32, file: std.fs.File, out: std.fs.File) !void {
        var buf: [65536]u8 = undefined;
        var total_read: u64 = 0;

        while (true) {
            const n = try file.read(&buf);
            if (n == 0) break;
            try out.writeAll(buf[0..n]);
            total_read += n;

            const progress: u8 = @intCast(@min(100, (total_read * 100) / self.local_size));
            self.setProgress(idx, progress, total_read);
        }
    }

    fn streamWithGzip(self: *Ship, idx: u32, file: std.fs.File, out: std.fs.File) !void {
        // Use gzip command as subprocess
        var gzip_child = std.process.Child.init(&.{ "gzip", "-c", "-1" }, self.allocator);
        gzip_child.stdin_behavior = .Pipe;
        gzip_child.stdout_behavior = .Pipe;
        gzip_child.stderr_behavior = .Pipe;
        try gzip_child.spawn();

        // store pid for stall detection kill
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.states[idx].gzip_pid = gzip_child.id;
        }
        defer {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.states[idx].gzip_pid = null;
        }

        const gzip_stdin = gzip_child.stdin.?;
        const gzip_stdout = gzip_child.stdout.?;

        // We need to handle this in a thread or use non-blocking I/O
        // For simplicity, spawn a thread to read from gzip and write to ssh
        const WriterContext = struct {
            src: std.fs.File,
            dst: std.fs.File,
            last_progress: *std.time.Instant,
            mutex: *std.Thread.Mutex,
        };

        var writer_last_progress = std.time.Instant.now() catch @panic("no clock");

        const writer_thread = try std.Thread.spawn(.{}, struct {
            fn run(ctx: WriterContext) void {
                var buf: [65536]u8 = undefined;
                while (true) {
                    const n = ctx.src.read(&buf) catch break;
                    if (n == 0) break;
                    ctx.dst.writeAll(buf[0..n]) catch break;
                    // update progress time - ssh accepted data
                    if (std.time.Instant.now()) |now| {
                        ctx.mutex.lock();
                        ctx.last_progress.* = now;
                        ctx.mutex.unlock();
                    } else |_| {}
                }
            }
        }.run, .{WriterContext{
            .src = gzip_stdout,
            .dst = out,
            .last_progress = &writer_last_progress,
            .mutex = &self.mutex,
        }});

        // Stream file to gzip stdin with progress
        var buf: [65536]u8 = undefined;
        var total_read: u64 = 0;
        var stream_err: ?anyerror = null;

        while (true) {
            const n = file.read(&buf) catch |e| {
                stream_err = e;
                break;
            };
            if (n == 0) break;
            gzip_stdin.writeAll(buf[0..n]) catch |e| {
                stream_err = e;
                break;
            };
            total_read += n;

            const progress: u8 = @intCast(@min(100, (total_read * 100) / self.local_size));
            // use writer's progress time (tracks ssh, not gzip input)
            {
                self.mutex.lock();
                self.states[idx].progress = progress;
                self.states[idx].bytes_sent = total_read;
                self.states[idx].last_progress_time = writer_last_progress;
                self.mutex.unlock();
            }
        }
        gzip_stdin.close();
        gzip_child.stdin = null;

        writer_thread.join();
        _ = gzip_child.wait() catch {};

        if (stream_err) |e| return e;
    }

    fn installFile(self: *Ship, idx: u32, spec: HostSpec, tmp_path: []const u8, dest: []const u8) !void {
        const escaped_tmp = try escapeRemotePath(self.allocator, tmp_path);
        defer self.allocator.free(escaped_tmp);
        const escaped_dest = try escapeShellArg(self.allocator, dest);
        defer self.allocator.free(escaped_dest);

        var cmds: std.ArrayList(u8) = .{};
        defer cmds.deinit(self.allocator);

        const sudo_prefix = if (self.config.opts.sudo) self.config.opts.sudo_cmd else "";
        const space = if (self.config.opts.sudo) " " else "";

        // mkdir -p parent
        const parent = std.fs.path.dirname(dest) orelse "/";
        const escaped_parent = try escapeShellArg(self.allocator, parent);
        defer self.allocator.free(escaped_parent);

        var cmd_buf: [4096]u8 = undefined;
        var pos: usize = 0;

        // Build command string
        pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}mkdir -p {s} && ", .{ sudo_prefix, space, escaped_parent }) catch unreachable).len;

        // chmod
        if (self.config.opts.chmod) |mode| {
            pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}chmod {o} {s} && ", .{ sudo_prefix, space, mode, escaped_tmp }) catch unreachable).len;
        }

        // chown
        if (self.config.opts.install_owner) |owner| {
            const escaped_owner = try escapeShellArg(self.allocator, owner);
            defer self.allocator.free(escaped_owner);
            pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}chown {s} {s} && ", .{ sudo_prefix, space, escaped_owner, escaped_tmp }) catch unreachable).len;
        }

        // mv
        pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}mv {s} {s}", .{ sudo_prefix, space, escaped_tmp, escaped_dest }) catch unreachable).len;

        const result = try self.runSshCommand(spec, cmd_buf[0..pos]);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (result.term.Exited != 0) {
            // store and print error immediately
            if (result.stderr.len > 0) {
                const first_line = if (std.mem.indexOf(u8, result.stderr, "\n")) |nl|
                    result.stderr[0..nl]
                else
                    result.stderr;
                if (first_line.len > 0) {
                    std.debug.print("\n{s}: {s}\n", .{ spec.host, first_line });
                    if (self.allocator.dupe(u8, first_line)) |msg| {
                        self.mutex.lock();
                        self.states[idx].error_msg = msg;
                        self.mutex.unlock();
                    } else |_| {}
                }
            }
            // check for sudo password prompt hint
            if (std.mem.indexOf(u8, result.stderr, "password") != null or
                std.mem.indexOf(u8, result.stderr, "sudo") != null)
            {
                return error.SudoRequiresPassword;
            }
            // cleanup tmp on failure (unless keep_tmp_on_fail)
            if (!self.config.opts.keep_tmp_on_fail) {
                const cleanup = try std.fmt.allocPrint(self.allocator, "rm -f {s}", .{escaped_tmp});
                defer self.allocator.free(cleanup);
                const cleanup_result = self.runSshCommand(spec, cleanup) catch return error.InstallFailed;
                self.allocator.free(cleanup_result.stdout);
                self.allocator.free(cleanup_result.stderr);
            }
            return error.InstallFailed;
        }
    }

    fn runRestart(self: *Ship, spec: HostSpec, cmd: []const u8) !void {
        const escaped_cmd = try escapeShellArg(self.allocator, cmd);
        defer self.allocator.free(escaped_cmd);

        const remote_cmd = if (self.config.opts.sudo)
            try std.fmt.allocPrint(self.allocator, "{s} sh -c {s}", .{ self.config.opts.sudo_cmd, escaped_cmd })
        else
            cmd;
        defer if (self.config.opts.sudo) self.allocator.free(remote_cmd);

        const result = try self.runSshCommand(spec, remote_cmd);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (result.term.Exited != 0) {
            return error.RestartFailed;
        }
    }

    fn progressLoop(self: *Ship, _: []std.Thread) !void {
        const stdout = std.fs.File.stdout();
        var all_done = false;
        var print_buf: [4096]u8 = undefined;

        // Calculate column width: max host label length, min 10 for "100% 999M" or similar
        var col_width: usize = 10;
        for (self.states) |state| {
            const label = self.getHostLabel(state.spec);
            if (label.len > col_width) col_width = label.len;
        }
        col_width += 1; // space between columns

        // Detect terminal width, limit visible hosts
        const term_width: usize = blk: {
            const native = @import("builtin").os.tag;
            if (native == .windows) {
                const kernel32 = std.os.windows.kernel32;
                var info: std.os.windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
                if (kernel32.GetConsoleScreenBufferInfo(stdout.handle, &info) != 0) {
                    const w = info.srWindow.Right - info.srWindow.Left + 1;
                    if (w > 0) break :blk @intCast(w);
                }
            } else {
                var wsz: std.posix.winsize = undefined;
                const rc = std.posix.system.ioctl(stdout.handle, std.posix.T.IOCGWINSZ, @intFromPtr(&wsz));
                if (rc == 0 and wsz.col > 0) break :blk wsz.col;
            }
            break :blk 80; // fallback
        };

        const max_by_width = if (term_width > col_width) term_width / col_width else 1;
        const max_visible = @min(self.config.opts.jobs, max_by_width);
        const show_summary = self.states.len > max_visible;

        // Print header row once
        if (self.output_tty) {
            var pos: usize = 0;
            for (self.states[0..@min(self.states.len, max_visible)]) |state| {
                const label = self.getHostLabel(state.spec);
                const written = std.fmt.bufPrint(print_buf[pos..], "{s}", .{label}) catch break;
                pos += written.len;
                const pad = col_width - label.len;
                @memset(print_buf[pos..][0..pad], ' ');
                pos += pad;
            }
            if (show_summary) {
                const extra = self.states.len - max_visible;
                const written = std.fmt.bufPrint(print_buf[pos..], "+{d} more", .{extra}) catch "";
                pos += written.len;
            }
            print_buf[pos] = '\n';
            pos += 1;
            stdout.writeAll(print_buf[0..pos]) catch {};
        }

        const stall_ns: u64 = @as(u64, self.config.opts.stall_timeout) * 1_000_000_000;

        while (!all_done) {
            std.Thread.sleep(100_000_000); // 100ms

            const now = std.time.Instant.now() catch continue;

            var pos: usize = 0;
            print_buf[pos] = '\r';
            pos += 1;
            all_done = true;

            // Summary counters for hidden hosts
            var summary_done: usize = 0;
            var summary_skip: usize = 0;
            var summary_fail: usize = 0;
            var summary_active: usize = 0;

            self.mutex.lock();
            for (self.states, 0..) |*state, i| {
                var status_buf: [16]u8 = undefined;
                const status_str: []const u8 = switch (state.status) {
                    .pending, .checking => blk: {
                        all_done = false;
                        break :blk "...";
                    },
                    .uploading => blk: {
                        all_done = false;
                        // Check for stall
                        const since_progress = now.since(state.last_progress_time);
                        if (since_progress > stall_ns) {
                            state.error_msg = "stalled";
                            if (state.child_pid) |pid| {
                                std.posix.kill(pid, std.posix.SIG.KILL) catch {};
                            }
                            if (state.gzip_pid) |pid| {
                                std.posix.kill(pid, std.posix.SIG.KILL) catch {};
                            }
                            if (i > std.math.maxInt(u32)) @panic("host index overflow");
                            self.setStatusLocked(@intCast(i), .failed);
                            break :blk "STALL";
                        }
                        // Calculate speed
                        const elapsed_ns = now.since(state.start_time);
                        if (elapsed_ns > 0 and state.bytes_sent > 0) {
                            const speed = @divTrunc(state.bytes_sent * 1_000_000_000, elapsed_ns);
                            const speed_kb = @divTrunc(speed, 1024);
                            if (speed_kb >= 1024) {
                                const speed_mb = @divTrunc(speed_kb, 1024);
                                break :blk std.fmt.bufPrint(&status_buf, "{d}% {d}M", .{ state.progress, speed_mb }) catch "?";
                            } else {
                                break :blk std.fmt.bufPrint(&status_buf, "{d}% {d}K", .{ state.progress, speed_kb }) catch "?";
                            }
                        }
                        break :blk std.fmt.bufPrint(&status_buf, "{d}%", .{state.progress}) catch "?";
                    },
                    .installing => blk: {
                        all_done = false;
                        break :blk "INS";
                    },
                    .restarting => blk: {
                        all_done = false;
                        break :blk "RST";
                    },
                    .done => "OK",
                    .skipped => "SKIP",
                    .failed => "ERR",
                };

                // Track hidden hosts for summary
                if (i >= max_visible) {
                    switch (state.status) {
                        .done => summary_done += 1,
                        .skipped => summary_skip += 1,
                        .failed => summary_fail += 1,
                        else => summary_active += 1,
                    }
                    continue;
                }

                @memcpy(print_buf[pos..][0..status_str.len], status_str);
                pos += status_str.len;
                // Pad to column width
                const pad = col_width - status_str.len;
                @memset(print_buf[pos..][0..pad], ' ');
                pos += pad;
            }
            self.mutex.unlock();

            // Show summary for hidden hosts
            if (show_summary) {
                const written = std.fmt.bufPrint(print_buf[pos..], "+{d}\u{2713} {d}\u{2717} {d}\u{21bb}", .{
                    summary_done + summary_skip,
                    summary_fail,
                    summary_active,
                }) catch "";
                pos += written.len;
            }

            if (self.output_tty) {
                @memcpy(print_buf[pos..][0..3], "\x1b[K");
                pos += 3;
                stdout.writeAll(print_buf[0..pos]) catch {};
            }
        }
    }

    fn getHostLabel(self: *Ship, spec: HostSpec) []const u8 {
        _ = self;
        // strip common domain suffixes
        var label = spec.host;
        if (std.mem.endsWith(u8, label, ".local")) {
            label = label[0 .. label.len - 6];
        }
        return label;
    }

    fn printFinalStatus(self: *Ship) !void {
        if (!self.output_tty) return; // already printed via logFinalLocked
        const stdout = std.fs.File.stdout();
        stdout.writeAll("\n") catch {};

        for (self.states) |state| {
            if (state.status == .failed) {
                const label = self.getHostLabel(state.spec);
                const msg = state.error_msg orelse "unknown error";
                var buf: [256]u8 = undefined;
                const line = std.fmt.bufPrint(&buf, "{s}: {s}\n", .{ label, msg }) catch continue;
                stdout.writeAll(line) catch {};
            }
        }
    }
};

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = parseArgs(allocator) catch |err| {
        std.debug.print("Error parsing arguments: {s}\n", .{@errorName(err)});
        return 2;
    };

    if (config == null) return 0; // help printed

    var ship = try Ship.init(allocator, config.?);
    defer ship.deinit();
    return try ship.run();
}

test "parseHostSpec" {
    const cases = [_]struct { input: []const u8, host: []const u8, user: ?[]const u8, dest: ?[]const u8 }{
        .{ .input = "myhost", .host = "myhost", .user = null, .dest = null },
        .{ .input = "root@myhost", .host = "myhost", .user = "root", .dest = null },
        .{ .input = "myhost:/usr/bin/foo", .host = "myhost", .user = null, .dest = "/usr/bin/foo" },
        .{ .input = "root@myhost:/usr/bin/foo", .host = "myhost", .user = "root", .dest = "/usr/bin/foo" },
    };

    for (cases) |c| {
        const result = parseHostSpec(c.input);
        try std.testing.expectEqualStrings(c.host, result.host);
        if (c.user) |expected| {
            try std.testing.expectEqualStrings(expected, result.user.?);
        } else {
            try std.testing.expect(result.user == null);
        }
        if (c.dest) |expected| {
            try std.testing.expectEqualStrings(expected, result.dest.?);
        } else {
            try std.testing.expect(result.dest == null);
        }
    }
}

test "escapeShellArg" {
    const allocator = std.testing.allocator;

    const simple = try escapeShellArg(allocator, "hello");
    defer allocator.free(simple);
    try std.testing.expectEqualStrings("'hello'", simple);

    const with_quote = try escapeShellArg(allocator, "it's");
    defer allocator.free(with_quote);
    try std.testing.expectEqualStrings("'it'\\''s'", with_quote);
}
