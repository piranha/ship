## rcp.zig

### Primary Use

Upload one local file to N hosts in parallel with:

* md5 skip
* optional gzip streaming
* atomic replace
* clean one-line progress

---

## CLI

### Command

```
deploypush [options] <local_path:default_remote_dest> <hostSpec...>
```

### hostSpec formats

1. `host`

   * uses default ssh user (ssh config or current user)
   * uses default remote dest from `<local:dest>`

2. `user@host`

   * uses that user
   * uses default remote dest

3. `host:dest`

   * uses default ssh user
   * overrides dest for that host

4. `user@host:dest`

   * overrides both user and dest

**Parsing rule:** split hostSpec at the **last** `:` (so IPv6 still tricky; acceptable limitation unless you add `[v6]:dest` support).

### Options

* `-j, --jobs <N>`: max parallel hosts (default: min(num_hosts, 8))
* `--ssh <path>`: ssh binary (default `ssh`)
* `--ssh-opts <string>`: appended ssh args (default: `-oBatchMode=yes -oConnectTimeout=5`)
* `--port <port>`: default port (optional)
* `--user <user>`: default user if hostSpec doesn’t include one (optional; otherwise let ssh config decide)
* `--skip-md5`: disable remote md5 check
* `--compress|--no-compress|--compress=auto`: default `auto`
* `--compress-level <1..9>`: default `1`
* `--chmod <mode>`: default `0755`
* `--no-chmod`
* `--tmp-dir <path>`: default `/tmp`
* `--tmp-name <template>`: default `deploypush.{basename}.{pid}.new`
* `--sudo`: install final move+chmod via sudo (details below)
* `--sudo-cmd <cmd>`: default `sudo -n` (non-interactive)
* `--sudo-path <path>`: default `sudo` (if you want)
* `--install-owner <user:group>`: optional (applies via sudo `chown`)
* `--timeout <sec>`: overall per-host timeout (optional)
* `--quiet`: no live line
* `--keep-tmp-on-fail`: don’t delete temp file on failure (debug)

Exit codes: `0` all ok, `1` any failure, `2` usage.

---

## Destination rules

### Default

Destination is taken from `<local_path:default_remote_dest>`.

### Overrides

If `hostSpec` includes `:dest`, use that for that host.

### Install steps depend on privilege mode

* Without `--sudo`: upload directly to `dest.new` in the same directory (requires permission).
* With `--sudo`: upload to `tmp` under user permissions, then `sudo mv` into `dest`.

---

## Sudo install mode (important)

### What user wants

“Upload to `/usr/bin/dest`, but do it as normal user to tmp and then move with sudo.”

### Behavior when `--sudo` enabled

Per host:

1. Determine `dest` (default or override).
2. Pick a temp file path writable by the SSH user, default:

   * `tmp = <tmp-dir>/<tmp-name>`
   * Example: `/tmp/deploypush.mybin.12345.new`
3. Upload data to `tmp` as normal user.
4. Run privileged install via `sudo -n` (non-interactive):

   * create parent dir if needed
   * chmod
   * optional chown
   * atomic move into place

#### Remote command sequence (conceptual)

Upload phase (stdin → temp):

* no-compress: `cat > "$tmp"`
* compress: `gunzip > "$tmp" || busybox gunzip > "$tmp"`

Install phase (sudo):

* `sudo -n mkdir -p "$(dirname "$dest")"` (if `--mkdir` behavior is desired; keep default true)
* `sudo -n chmod 0755 "$tmp"` (unless `--no-chmod`)
* optional: `sudo -n chown user:group "$tmp"` (if `--install-owner`)
* `sudo -n mv "$tmp" "$dest"`

**Fail rules:**

* If sudo is requested and `sudo -n` fails (needs password), mark host as FAILED with clear error:

  * `"sudo requires password or not permitted"`
* Always best-effort cleanup temp on failure (unless `--keep-tmp-on-fail`).

### md5 skipping in sudo mode

Remote md5 check should still target the final `dest` path (not temp):

* `sudo` is NOT required just to read md5 unless permissions forbid it.
* Try without sudo first:

  * `md5sum "$dest" ...`
* If that fails due to permission and `--sudo` is on, retry with sudo:

  * `sudo -n md5sum "$dest" ...`

This avoids unnecessary uploads.

---

## MD5 check spec

Remote checksum command should be BusyBox-safe:

Try in this order:

1. `md5sum "$path"`
2. `busybox md5sum "$path"`
3. if still not available: treat as “unknown” (do upload)

When extracting:

* take first token of output.

---

## Compression spec

Default `auto`:

* Use gzip if:

  * local size ≥ 512 KiB AND
  * remote has gunzip (`command -v gunzip` or `busybox gunzip` works)
* gzip level default `1`

Implementation detail:

* progress percent is based on raw bytes read from local file (not compressed bytes).

---

## Progress output spec (one line)

### Display format

One line updated ~10Hz:

```
a:12% b:SKIP c:99% d:ERR
```

* `SKIP`: md5 matched
* `ERR`: failed (final state); optionally show last error after completion as separate lines

### Host label formatting

* Use hostSpec “host” part without user by default (`root@x` displays as `x`), unless duplicates; then include user.
* Optionally shorten domain (`x.local` → `x`).

### Rendering

* `\r` + line + ANSI clear-to-EOL `\x1b[K`
* Finish with newline once everything is done.
* After newline, print summary failures only.

---

## Concurrency model

* Worker pool with max `jobs`
* Each worker handles one host end-to-end
* Shared atomic/locked status array for renderer

---

## SSH execution details

### Respect ssh config/default user

* If hostSpec has no user and no `--user`, call ssh with just `host`.
* Let ssh resolve user from config or current user.
* If `--user` provided, prefer passing `-l user` unless hostSpec already contains `user@`.

### Avoid building unsafe shell strings

* Use exec argv arrays for local process spawning.
* For remote: you will still run `sh -c '...'`, so implement strict single-quote escaping for paths.

### Timeouts

* Optionally enforce per-host overall timeout by killing ssh/gzip processes if exceeded.

---

## Edge cases & expectations

* IPv6: either document limitation or support `[addr]:dest` syntax.
* Dest with spaces: supported via proper remote quoting.
* If remote disconnects mid-upload: mark failed; cleanup best-effort.

---

## Acceptance tests

1. Deploy to a normal Linux host using dest in `/home/user/bin` without sudo.
2. Deploy to a host requiring `/usr/local/bin` with `--sudo` where user has passwordless sudo; should succeed.
3. Deploy to host where sudo prompts for password; should fail fast with a clear message.
4. MD5 skip works in both normal and sudo mode.
5. One-line progress stays clean; after completion only summary lines remain.

---

## Implementation note: “sudo install” UX

Add a helpful hint in error:

* “sudo -n failed; configure passwordless sudo for mv/chmod or run with a user that can write the destination”

---

If you want one extra quality-of-life feature that’s worth it:
**`--restart <cmd>`** executed after successful install (optionally via sudo). That’s perfect for your “deploy binary to HW test devices” loop.

If you say “yes”, I’ll extend the spec with a clean restart hook (including `systemctl` vs BusyBox init scripts).

