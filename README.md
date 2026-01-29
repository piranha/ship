# ship

Fast parallel file deployment to multiple hosts over SSH.

```
$ ship ./myapp:/usr/local/bin/myapp host1 host2 host3 host4
host1      host2      host3      host4
OK         85% 24M    OK         INS
```

## Features

- **Parallel uploads** - configurable concurrency with `-j`
- **MD5 skip** - skip upload if remote file matches
- **Gzip compression** - auto-enabled for large files
- **Atomic install** - upload to temp, then mv into place
- **Sudo support** - upload as user, install as root
- **Progress display** - per-host status with transfer speed
- **Stall detection** - fail fast if transfer hangs
- **Restart hook** - run command after successful deploy

## Install

```bash
# Build from source (requires Zig 0.15+)
zig build --release=fast -Dstrip=true
cp zig-out/bin/ship /usr/local/bin/
```

## Usage

```
ship [options] <local_path:remote_dest> <host...>
```

### Host formats

```
host              # use ssh config defaults
user@host         # specify user  
host:/other/path  # override dest for this host
user@host:/path   # override both
```

### Examples

```bash
# Deploy binary to 3 hosts
ship ./myapp:/usr/local/bin/myapp web1 web2 web3

# With sudo (upload as user, mv as root)
ship --sudo ./nginx.conf:/etc/nginx/nginx.conf web1 web2

# Restart service after deploy
ship --sudo --restart "systemctl restart myapp" ./myapp:/usr/local/bin/myapp web1 web2

# Override dest per host
ship ./config:/etc/myapp/config web1:/etc/myapp/config.web1 web2

# Skip MD5 check, force upload
ship --skip-md5 ./myapp:/usr/local/bin/myapp web1

# Custom SSH options
ship --ssh-opts "-i ~/.ssh/deploy_key -o ConnectTimeout=10" ./app:/opt/app host1
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `-j, --jobs <N>` | min(hosts, 8) | Max parallel uploads |
| `--ssh <path>` | ssh | SSH binary |
| `--ssh-opts <str>` | -oBatchMode=yes -oConnectTimeout=5 | SSH options |
| `--port <port>` | - | Default SSH port |
| `--user <user>` | - | Default SSH user |
| `--skip-md5` | false | Skip remote MD5 check |
| `--compress` | auto | Force gzip compression |
| `--no-compress` | - | Disable compression |
| `--compress-level <1-9>` | 1 | Gzip level |
| `--chmod <mode>` | 0755 | File mode (octal) |
| `--no-chmod` | - | Skip chmod |
| `--sudo` | false | Use sudo for install |
| `--sudo-cmd <cmd>` | sudo -n | Sudo command |
| `--install-owner <u:g>` | - | Set owner:group via sudo |
| `--timeout <sec>` | 30 | SSH timeout |
| `--stall-timeout <sec>` | 10 | Fail if no progress for N sec |
| `--restart <cmd>` | - | Run after successful install |
| `--quiet` | false | No progress output |
| `--keep-tmp-on-fail` | false | Keep temp file on failure |

## Progress Display

```
host1      host2      host3      +2 more
OK         85% 24M    INS        +1✓ 0✗ 1↻
```

- **Percentage + speed** during upload (e.g., `85% 24M` = 85% done at 24 MB/s)
- **Status codes**: `OK` done, `SKIP` md5 matched, `ERR` failed, `INS` installing, `RST` restarting, `STALL` transfer hung
- **Summary** for overflow hosts: ✓ done/skipped, ✗ failed, ↻ running

Display auto-fits terminal width; excess hosts shown in summary.

## How It Works

1. **MD5 check** - compare local MD5 with remote (skip if match)
2. **Upload** - stream file to temp path via SSH (optionally gzipped)
3. **Install** - chmod + atomic mv to final dest (via sudo if enabled)
4. **Restart** - run restart command if specified

Temp file pattern: `/tmp/ship.{basename}.{pid}.new`

## Requirements

- Remote: any POSIX system with `cat`, `mv`, `chmod`, `md5sum` (or busybox equivalents)
- Local: Zig 0.15+ to build

## Exit Codes

- `0` - all hosts succeeded
- `1` - one or more hosts failed
- `2` - usage error
