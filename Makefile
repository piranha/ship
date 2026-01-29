.PHONY: build release clean test run

build:
	zig build

release:
	zig build --release=fast -Dstrip=true

clean:
	rm -rf zig-out .zig-cache

test:
	zig build test
	zig build
	@./test/setup.sh
	@./test/integration.sh
	@./test/teardown.sh

run:
	zig build run -- $(ARGS)
