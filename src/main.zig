const std = @import("std");

const Config = struct {
    local_path: []const u8,
    default_dest: []const u8,
    hosts: []HostSpec,
    jobs: u32,
    ssh_path: []const u8,
    ssh_opts: []const u8,
    default_port: ?u16,
    default_user: ?[]const u8,
    skip_md5: bool,
    compress: CompressMode,
    compress_level: u4,
    chmod: ?u16,
    tmp_dir: []const u8,
    tmp_name: []const u8,
    sudo: bool,
    sudo_cmd: []const u8,
    install_owner: ?[]const u8,
    timeout: ?u32,
    stall_timeout: u32,
    quiet: bool,
    keep_tmp_on_fail: bool,
    restart_cmd: ?[]const u8,
};

const CompressMode = enum { auto, on, off };

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

fn parseArgs(allocator: std.mem.Allocator) !?Config {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // skip program name

    var jobs: u32 = 8;
    var ssh_path: []const u8 = "ssh";
    var ssh_opts: []const u8 = "-oBatchMode=yes -oConnectTimeout=5";
    var default_port: ?u16 = null;
    var default_user: ?[]const u8 = null;
    var skip_md5 = false;
    var compress: CompressMode = .auto;
    var compress_level: u4 = 1;
    var chmod: ?u16 = 0o755;
    var tmp_dir: []const u8 = "/tmp";
    var tmp_name: []const u8 = "ship.{basename}.{pid}.new";
    var sudo = false;
    var sudo_cmd: []const u8 = "sudo -n";
    var install_owner: ?[]const u8 = null;
    var timeout: ?u32 = null;
    var stall_timeout: u32 = 10;
    var quiet = false;
    var keep_tmp_on_fail = false;
    var restart_cmd: ?[]const u8 = null;

    var local_path: ?[]const u8 = null;
    var default_dest: ?[]const u8 = null;
    var hosts: std.ArrayList(HostSpec) = .{};
    defer hosts.deinit(allocator);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return null;
        } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--jobs")) {
            const val = args.next() orelse return error.MissingValue;
            jobs = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, arg, "--ssh")) {
            ssh_path = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--ssh-opts")) {
            ssh_opts = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const val = args.next() orelse return error.MissingValue;
            default_port = try std.fmt.parseInt(u16, val, 10);
        } else if (std.mem.eql(u8, arg, "--user")) {
            default_user = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--skip-md5")) {
            skip_md5 = true;
        } else if (std.mem.eql(u8, arg, "--compress")) {
            compress = .on;
        } else if (std.mem.eql(u8, arg, "--no-compress")) {
            compress = .off;
        } else if (std.mem.eql(u8, arg, "--compress=auto")) {
            compress = .auto;
        } else if (std.mem.eql(u8, arg, "--compress-level")) {
            const val = args.next() orelse return error.MissingValue;
            compress_level = try std.fmt.parseInt(u4, val, 10);
        } else if (std.mem.eql(u8, arg, "--chmod")) {
            const val = args.next() orelse return error.MissingValue;
            chmod = try std.fmt.parseInt(u16, val, 8);
        } else if (std.mem.eql(u8, arg, "--no-chmod")) {
            chmod = null;
        } else if (std.mem.eql(u8, arg, "--tmp-dir")) {
            tmp_dir = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--tmp-name")) {
            tmp_name = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--sudo")) {
            sudo = true;
        } else if (std.mem.eql(u8, arg, "--sudo-cmd")) {
            sudo_cmd = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--install-owner")) {
            install_owner = args.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            const val = args.next() orelse return error.MissingValue;
            timeout = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, arg, "--stall-timeout")) {
            const val = args.next() orelse return error.MissingValue;
            stall_timeout = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--keep-tmp-on-fail")) {
            keep_tmp_on_fail = true;
        } else if (std.mem.eql(u8, arg, "--restart")) {
            restart_cmd = args.next() orelse return error.MissingValue;
        } else if (arg[0] == '-') {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        } else {
            // positional arg
            if (local_path == null) {
                // parse local_path:default_dest
                if (std.mem.indexOf(u8, arg, ":")) |idx| {
                    local_path = arg[0..idx];
                    default_dest = arg[idx + 1 ..];
                } else {
                    std.debug.print("First argument must be local_path:remote_dest\n", .{});
                    return error.InvalidArgument;
                }
            } else {
                try hosts.append(allocator, parseHostSpec(arg));
            }
        }
    }

    if (local_path == null or hosts.items.len == 0) {
        printUsage();
        return null;
    }

    if (jobs > hosts.items.len) jobs = @intCast(hosts.items.len);

    return .{
        .local_path = local_path.?,
        .default_dest = default_dest.?,
        .hosts = try hosts.toOwnedSlice(allocator),
        .jobs = jobs,
        .ssh_path = ssh_path,
        .ssh_opts = ssh_opts,
        .default_port = default_port,
        .default_user = default_user,
        .skip_md5 = skip_md5,
        .compress = compress,
        .compress_level = compress_level,
        .chmod = chmod,
        .tmp_dir = tmp_dir,
        .tmp_name = tmp_name,
        .sudo = sudo,
        .sudo_cmd = sudo_cmd,
        .install_owner = install_owner,
        .timeout = timeout,
        .stall_timeout = stall_timeout,
        .quiet = quiet,
        .keep_tmp_on_fail = keep_tmp_on_fail,
        .restart_cmd = restart_cmd,
    };
}

fn printUsage() void {
    const usage =
        \\Usage: ship [options] <local_path:remote_dest> <host...>
        \\
        \\Upload a file to multiple hosts in parallel.
        \\
        \\Host formats:
        \\  host              use default user and dest
        \\  user@host         specify user
        \\  host:dest         override dest for this host
        \\  user@host:dest    override both
        \\
        \\Options:
        \\  -h, --help              Show this help
        \\  -j, --jobs <N>          Max parallel hosts (default: min(hosts, 8))
        \\  --ssh <path>            SSH binary (default: ssh)
        \\  --ssh-opts <string>     SSH options (default: -oBatchMode=yes -oConnectTimeout=5)
        \\  --port <port>           Default SSH port
        \\  --user <user>           Default SSH user
        \\  --skip-md5              Skip remote MD5 check
        \\  --compress              Force gzip compression
        \\  --no-compress           Disable compression
        \\  --compress-level <1-9>  Gzip level (default: 1)
        \\  --chmod <mode>          File mode in octal (default: 0755)
        \\  --no-chmod              Skip chmod
        \\  --tmp-dir <path>        Temp directory (default: /tmp)
        \\  --tmp-name <template>   Temp filename template
        \\  --sudo                  Use sudo for install
        \\  --sudo-cmd <cmd>        Sudo command (default: sudo -n)
        \\  --install-owner <u:g>   Set owner:group via sudo
        \\  --timeout <sec>         SSH timeout (default: 30)
        \\  --stall-timeout <sec>   Fail if no progress for N sec (default: 10)
        \\  --quiet                 No progress output
        \\  --keep-tmp-on-fail      Keep temp file on failure
        \\  --restart <cmd>         Command to run after successful install
        \\
    ;
    std.debug.print("{s}", .{usage});
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
        self.use_compression = switch (self.config.compress) {
            .on => true,
            .off => false,
            .auto => self.local_size >= 512 * 1024,
        };

        // spawn workers
        var threads = try self.allocator.alloc(std.Thread, self.config.jobs);
        var next_host: u32 = 0;

        for (0..self.config.jobs) |i| {
            threads[i] = try std.Thread.spawn(.{}, workerThread, .{ self, &next_host });
        }

        // progress display loop
        if (!self.config.quiet) {
            try self.progressLoop(threads);
        }

        for (threads) |t| t.join();
        self.allocator.free(threads);

        // final status line
        if (!self.config.quiet) {
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
                self.states[idx].status = .failed;
                self.states[idx].error_msg = @errorName(err);
                self.failed_count += 1;
            };
        }
    }

    fn processHost(self: *Ship, idx: u32) !void {
        const state = &self.states[idx];
        const spec = state.spec;
        const dest = spec.dest orelse self.config.default_dest;

        // md5 check
        if (!self.config.skip_md5) {
            self.setStatus(idx, .checking);
            const remote_md5 = try self.getRemoteMd5(spec, dest);
            if (remote_md5) |md5| {
                if (std.mem.eql(u8, &md5, self.local_md5)) {
                    self.setStatus(idx, .skipped);
                    return;
                }
            }
        }

        // upload
        self.setStatus(idx, .uploading);
        const tmp_path = try self.getTmpPath(spec);
        defer self.allocator.free(tmp_path);
        try self.uploadFile(idx, spec, tmp_path);

        // install
        self.setStatus(idx, .installing);
        try self.installFile(spec, tmp_path, dest);

        // restart
        if (self.config.restart_cmd) |cmd| {
            self.setStatus(idx, .restarting);
            try self.runRestart(spec, cmd);
        }

        self.setStatus(idx, .done);
    }

    fn setStatus(self: *Ship, idx: u32, status: HostStatus) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.states[idx].status = status;
        if (status == .failed) self.failed_count += 1;
        if (status == .uploading) {
            const now = std.time.Instant.now() catch return;
            self.states[idx].start_time = now;
            self.states[idx].last_progress_time = now;
        }
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

        try result.args.append(self.allocator, self.config.ssh_path);

        // parse and add ssh_opts
        var it = std.mem.splitScalar(u8, self.config.ssh_opts, ' ');
        while (it.next()) |opt| {
            if (opt.len > 0) try result.args.append(self.allocator, opt);
        }

        // Add timeout via SSH options (ServerAliveInterval=timeout, ServerAliveCountMax=1)
        const timeout = self.config.timeout orelse 30; // default 30s
        result.timeout_str = try std.fmt.allocPrint(self.allocator, "-oServerAliveInterval={d}", .{timeout});
        try result.args.append(self.allocator, result.timeout_str.?);
        try result.args.append(self.allocator, "-oServerAliveCountMax=1");

        if (self.config.default_port) |port| {
            try result.args.append(self.allocator, "-p");
            result.port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{port});
            try result.args.append(self.allocator, result.port_str.?);
        }

        const user = spec.user orelse self.config.default_user;
        if (user) |u| {
            try result.args.append(self.allocator, "-l");
            try result.args.append(self.allocator, u);
        }

        try result.args.append(self.allocator, spec.host);
        return result;
    }

    fn getRemoteMd5(self: *Ship, spec: HostSpec, dest: []const u8) !?[32]u8 {
        const escaped_dest = try escapeShellArg(self.allocator, dest);
        defer self.allocator.free(escaped_dest);

        // try md5sum, then busybox md5sum
        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "md5sum {s} 2>/dev/null || busybox md5sum {s} 2>/dev/null",
            .{ escaped_dest, escaped_dest },
        );
        defer self.allocator.free(cmd);

        var result = try self.runSshCommand(spec, cmd);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (result.term.Exited == 0 and result.stdout.len >= 32) {
            var md5: [32]u8 = undefined;
            @memcpy(&md5, result.stdout[0..32]);
            return md5;
        }

        // try with sudo if enabled
        if (self.config.sudo) {
            const sudo_cmd = try std.fmt.allocPrint(
                self.allocator,
                "{s} md5sum {s} 2>/dev/null || {s} busybox md5sum {s} 2>/dev/null",
                .{ self.config.sudo_cmd, escaped_dest, self.config.sudo_cmd, escaped_dest },
            );
            defer self.allocator.free(sudo_cmd);

            var sudo_result = try self.runSshCommand(spec, sudo_cmd);
            defer self.allocator.free(sudo_result.stdout);
            defer self.allocator.free(sudo_result.stderr);
            if (sudo_result.term.Exited == 0 and sudo_result.stdout.len >= 32) {
                var md5: [32]u8 = undefined;
                @memcpy(&md5, sudo_result.stdout[0..32]);
                return md5;
            }
        }

        return null;
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

    fn getTmpPath(self: *Ship, spec: HostSpec) ![]const u8 {
        _ = spec;
        const basename = std.fs.path.basename(self.config.local_path);
        const pid = std.os.linux.getpid();

        // simple template substitution
        var result: std.ArrayList(u8) = .{};
        errdefer result.deinit(self.allocator);
        try result.appendSlice(self.allocator, self.config.tmp_dir);
        try result.append(self.allocator, '/');

        var i: usize = 0;
        while (i < self.config.tmp_name.len) {
            if (std.mem.startsWith(u8, self.config.tmp_name[i..], "{basename}")) {
                try result.appendSlice(self.allocator, basename);
                i += 10;
            } else if (std.mem.startsWith(u8, self.config.tmp_name[i..], "{pid}")) {
                var pid_buf: [16]u8 = undefined;
                const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch unreachable;
                try result.appendSlice(self.allocator, pid_str);
                i += 5;
            } else {
                try result.append(self.allocator, self.config.tmp_name[i]);
                i += 1;
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn uploadFile(self: *Ship, idx: u32, spec: HostSpec, tmp_path: []const u8) !void {
        const escaped_tmp = try escapeShellArg(self.allocator, tmp_path);
        defer self.allocator.free(escaped_tmp);

        // check if remote has gunzip (for auto mode)
        var actually_compress = self.use_compression;
        if (self.config.compress == .auto and self.use_compression) {
            const check_cmd = "command -v gunzip >/dev/null 2>&1 || command -v busybox >/dev/null 2>&1";
            const result = try self.runSshCommand(spec, check_cmd);
            defer self.allocator.free(result.stdout);
            defer self.allocator.free(result.stderr);
            if (result.term.Exited != 0) {
                actually_compress = false;
            }
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

        const term = try child.wait();
        if (term.Exited != 0) {
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

        const gzip_stdin = gzip_child.stdin.?;
        const gzip_stdout = gzip_child.stdout.?;

        // We need to handle this in a thread or use non-blocking I/O
        // For simplicity, spawn a thread to read from gzip and write to ssh
        const ReadWriteContext = struct {
            src: std.fs.File,
            dst: std.fs.File,
        };

        const writer_thread = try std.Thread.spawn(.{}, struct {
            fn run(ctx: ReadWriteContext) void {
                var buf: [65536]u8 = undefined;
                while (true) {
                    const n = ctx.src.read(&buf) catch break;
                    if (n == 0) break;
                    ctx.dst.writeAll(buf[0..n]) catch break;
                }
            }
        }.run, .{ReadWriteContext{ .src = gzip_stdout, .dst = out }});

        // Stream file to gzip stdin with progress
        var buf: [65536]u8 = undefined;
        var total_read: u64 = 0;

        while (true) {
            const n = try file.read(&buf);
            if (n == 0) break;
            try gzip_stdin.writeAll(buf[0..n]);
            total_read += n;

            const progress: u8 = @intCast(@min(100, (total_read * 100) / self.local_size));
            self.setProgress(idx, progress, total_read);
        }
        gzip_stdin.close();
        gzip_child.stdin = null;

        writer_thread.join();
        _ = try gzip_child.wait();
    }

    fn installFile(self: *Ship, spec: HostSpec, tmp_path: []const u8, dest: []const u8) !void {
        const escaped_tmp = try escapeShellArg(self.allocator, tmp_path);
        defer self.allocator.free(escaped_tmp);
        const escaped_dest = try escapeShellArg(self.allocator, dest);
        defer self.allocator.free(escaped_dest);

        var cmds: std.ArrayList(u8) = .{};
        defer cmds.deinit(self.allocator);

        const sudo_prefix = if (self.config.sudo) self.config.sudo_cmd else "";
        const space = if (self.config.sudo) " " else "";

        // mkdir -p parent
        const parent = std.fs.path.dirname(dest) orelse "/";
        const escaped_parent = try escapeShellArg(self.allocator, parent);
        defer self.allocator.free(escaped_parent);

        var cmd_buf: [4096]u8 = undefined;
        var pos: usize = 0;

        // Build command string
        pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}mkdir -p {s} && ", .{ sudo_prefix, space, escaped_parent }) catch unreachable).len;

        // chmod
        if (self.config.chmod) |mode| {
            pos += (std.fmt.bufPrint(cmd_buf[pos..], "{s}{s}chmod {o} {s} && ", .{ sudo_prefix, space, mode, escaped_tmp }) catch unreachable).len;
        }

        // chown
        if (self.config.install_owner) |owner| {
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
            // check for sudo password prompt hint
            if (std.mem.indexOf(u8, result.stderr, "password") != null or
                std.mem.indexOf(u8, result.stderr, "sudo") != null)
            {
                return error.SudoRequiresPassword;
            }
            // cleanup tmp on failure (unless keep_tmp_on_fail)
            if (!self.config.keep_tmp_on_fail) {
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

        const remote_cmd = if (self.config.sudo)
            try std.fmt.allocPrint(self.allocator, "{s} sh -c {s}", .{ self.config.sudo_cmd, escaped_cmd })
        else
            cmd;
        defer if (self.config.sudo) self.allocator.free(remote_cmd);

        const result = try self.runSshCommand(spec, remote_cmd);
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (result.term.Exited != 0) {
            return error.RestartFailed;
        }
    }

    fn progressLoop(self: *Ship, threads: []std.Thread) !void {
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
            var wsz: std.posix.winsize = undefined;
            const rc = std.posix.system.ioctl(stdout.handle, std.posix.T.IOCGWINSZ, @intFromPtr(&wsz));
            if (rc == 0 and wsz.col > 0) break :blk wsz.col;
            break :blk 80; // fallback
        };

        const max_by_width = if (term_width > col_width) term_width / col_width else 1;
        const max_visible = @min(self.config.jobs, max_by_width);
        const show_summary = self.states.len > max_visible;

        // Print header row once
        {
            var pos: usize = 0;
            for (self.states[0..@min(self.states.len, max_visible)]) |state| {
                const label = self.getHostLabel(state.spec);
                const written = std.fmt.bufPrint(print_buf[pos..], "{s}", .{label}) catch break;
                pos += written.len;
                // Pad to column width
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

        const stall_ns: u64 = @as(u64, self.config.stall_timeout) * 1_000_000_000;

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
                            state.status = .failed;
                            state.error_msg = "stalled";
                            self.failed_count += 1;
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

            // ANSI clear to EOL
            @memcpy(print_buf[pos..][0..3], "\x1b[K");
            pos += 3;

            stdout.writeAll(print_buf[0..pos]) catch {};

            // check if threads still alive
            for (threads) |t| {
                _ = t.getHandle();
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
        const stdout = std.fs.File.stdout();
        stdout.writeAll("\n") catch {};

        // print errors
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
