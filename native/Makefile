CC ?= gcc
CLANG ?= $(shell command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || echo clang)
CPPFLAGS = -I./drawterm/include -I./drawterm -I.
CFLAGS = $(CPPFLAGS) -O2 -Wall
SANITIZER_CFLAGS = $(CPPFLAGS) -O1 -g -fno-omit-frame-pointer -Wall -fsanitize=address,undefined
FUZZER_CFLAGS = $(CPPFLAGS) -O1 -g -fno-omit-frame-pointer -Wall -fsanitize=fuzzer,address,undefined

LIBC = drawterm/libc/libc.a
LIBMP = drawterm/libmp/libmp.a
LIBSEC = drawterm/libsec/libsec.a
LIBAUTHSRV = drawterm/libauthsrv/libauthsrv.a
LIBSTUBS = libstubs.a
LIBMACHDEP = libmachdep.a
NATIVE_LIBS = -Wl,--start-group $(LIBAUTHSRV) $(LIBSEC) $(LIBMP) $(LIBC) $(LIBSTUBS) $(LIBMACHDEP) -Wl,--end-group -lm -lpthread
TOOL = dp9ik_native_tool
TOOL_OBJ = dp9ik_native_tool.o
SANITIZED_TOOL = dp9ik_native_tool_san
FUZZ_TOOL = dp9ik_native_tool_fuzz
FUZZ_SRC = dp9ik_native_tool_fuzz.c

.PHONY: all clean sanitize fuzz fuzz-smoke

all: $(TOOL)

sanitize: $(SANITIZED_TOOL)

fuzz: $(FUZZ_TOOL)

fuzz-smoke: $(FUZZ_TOOL)
	ASAN_OPTIONS=detect_leaks=0 ./$(FUZZ_TOOL) -runs=100

$(TOOL): $(TOOL_OBJ) $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV) $(LIBSTUBS) $(LIBMACHDEP)
	$(CC) -o $@ $(TOOL_OBJ) $(NATIVE_LIBS)

$(TOOL_OBJ): dp9ik_native_tool.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SANITIZED_TOOL): dp9ik_native_tool.c $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV) $(LIBSTUBS) $(LIBMACHDEP)
	$(CLANG) $(SANITIZER_CFLAGS) -o $@ $< $(NATIVE_LIBS)

$(FUZZ_TOOL): $(FUZZ_SRC) $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV) $(LIBSTUBS) $(LIBMACHDEP)
	$(CLANG) $(FUZZER_CFLAGS) -o $@ $< $(NATIVE_LIBS)

clean:
	rm -f $(TOOL_OBJ) $(TOOL) $(SANITIZED_TOOL) $(FUZZ_TOOL)
