CC = gcc
CFLAGS = -I./drawterm/include -I./drawterm -I. -O2 -Wall

LIBC = drawterm/libc/libc.a
LIBMP = drawterm/libmp/libmp.a
LIBSEC = drawterm/libsec/libsec.a
LIBAUTHSRV = drawterm/libauthsrv/libauthsrv.a
LIBSTUBS = libstubs.a
LIBMACHDEP = libmachdep.a
TOOL = dp9ik_native_tool
TOOL_OBJ = dp9ik_native_tool.o

.PHONY: all clean

all: $(TOOL)

$(TOOL): $(TOOL_OBJ) $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV) $(LIBSTUBS) $(LIBMACHDEP)
	$(CC) -o $@ $(TOOL_OBJ) -Wl,--start-group $(LIBAUTHSRV) $(LIBSEC) $(LIBMP) $(LIBC) $(LIBSTUBS) $(LIBMACHDEP) -Wl,--end-group -lm -lpthread

$(TOOL_OBJ): dp9ik_native_tool.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TOOL_OBJ) $(TOOL)
