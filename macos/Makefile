CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
WARNINGS = -std=c11 -Wall -Wextra -Werror -Wpedantic

.PHONY: all test test-runtime-isolated sanitize clean
all: build/natcap-macos

build:
	mkdir -p $@

build/natcap-macos: natcap_macos.c natcap_codec.c natcap_codec.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) natcap_macos.c natcap_codec.c -o $@

build/test-codec: tests/test_codec.c natcap_codec.c natcap_codec.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -I. tests/test_codec.c natcap_codec.c -o $@

build/test-runtime: tests/test_runtime.c natcap_macos.c natcap_codec.c natcap_codec.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -I. tests/test_runtime.c natcap_codec.c -o $@

test: build/test-codec build/test-runtime build/natcap-macos
	./build/test-codec
	./build/test-runtime
	python3 tests/test_cli.py ./build/natcap-macos

# Optional Linux integration test; touches only a new private network namespace.
test-runtime-isolated: build/test-runtime
	unshare -Urn sh -c 'ip link set lo up && NATCAP_TEST_ISOLATED=1 exec ./build/test-runtime'

sanitize: | build
	$(CC) $(CPPFLAGS) -O1 -g $(WARNINGS) -fsanitize=address,undefined -fno-omit-frame-pointer -I. tests/test_codec.c natcap_codec.c -o build/test-codec-sanitize
	./build/test-codec-sanitize

clean:
	rm -rf build
