.PHONY: build release clean unittest test run ciall

build:
	zig build

release:
	zig build --release=fast -Dstrip=true

clean:
	rm -rf zig-out .zig-cache

unittest:
	zig build test

test: unittest
	zig build
	@./test/setup.sh
	@./test/integration.sh
	@./test/teardown.sh

run:
	zig build run -- $(ARGS)

ifndef VERSION
ciall:
	$(error VERSION is not set)
else
ciall:
	zig build --release=fast -Dstrip=true -Dversion=${VERSION} -Dtarget=x86_64-linux-musl  -Doutput=dist/ship-Linux-x86_64
	zig build --release=fast -Dstrip=true -Dversion=${VERSION} -Dtarget=aarch64-linux-musl -Doutput=dist/ship-Linux-aarch64
	zig build --release=fast -Dstrip=true -Dversion=${VERSION} -Dtarget=x86_64-macos       -Doutput=dist/ship-Darwin-x86_64
	zig build --release=fast -Dstrip=true -Dversion=${VERSION} -Dtarget=aarch64-macos      -Doutput=dist/ship-Darwin-arm64
# windows is just too damn complicated to support when I don't really need it
#	zig build --release=fast -Dstrip=true -Dversion=${VERSION} -Dtarget=x88_64-windows     -Doutput=dist/ship-Windows-x86_64.exe
endif
