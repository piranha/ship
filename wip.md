# ship implementation

## Status: Complete - all tests passing

## Phases
1. [x] Project setup (build.zig, Makefile)
2. [x] CLI arg parsing
3. [x] Host spec parsing
4. [x] MD5 check (remote)
5. [x] File upload (with optional gzip via subprocess)
6. [x] Sudo install mode
7. [x] Progress display
8. [x] Worker pool / concurrency
9. [x] --restart feature
10. [x] Integration tests (9 tests)
11. [x] Memory leak fixes

## Integration Tests
All passing:
1. Basic upload - file transfer with MD5 verification
2. MD5 skip - skip upload when remote matches
3. Multi-host parallel upload
4. Custom chmod
5. Path with spaces
6. Compression (gzip)
7. Unreachable host handling
8. Restart command execution
9. Dest override per host

## Notes
- Compression uses gzip subprocess (not zig std lib) for simplicity
- Fixed double-close bug on stdin in child processes
- Fixed memory leaks from runSshCommand stdout/stderr
- Test env uses local sshd instances on ports 17722-17724

## Binary size
~260KB stripped (ReleaseFast)
