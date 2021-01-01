CFLAGS	?= -DRIOTBUILD -DRIOTSECP384R1 -Os

# REMOVE -Wno* BELOW
WARNING_CFLAGS ?=  -Wall -Wextra

INCLUDES ?= -I./RIoTCrypt/include -I./include
LOCAL_CFLAGS = $(WARNING_CFLAGS) $(INCLUDES) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L./RIoTCrypt -lmbedcrypto

# DEBUG
#LOCAL_CFLAGS += -g3 -O0

.SILENT:

.PHONY: all clean

all: riotester

riotester: lib RIoTester.o
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) RIoTester.o $(LOCAL_LDFLAGS) -o $@

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

lib:
	make CRYPTO_INCLUDES:="-I../RIoTCrypt/include -I../include" -C RIoTCrypt

clean:
	rm -f *.o ./RIoTCrypt/*.o ./RIoTCrypt/libmbed*

