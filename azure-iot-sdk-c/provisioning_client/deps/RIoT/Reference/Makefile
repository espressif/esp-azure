CFLAGS	?= -DRIOTBUILD -DRIOTSECP384R1 -Os

WARNING_CFLAGS ?=  -Wall -Wextra

INCLUDES ?= -I./RIoT/RIoTCrypt/include -I./RIoT/include
LOCAL_CFLAGS = $(WARNING_CFLAGS) $(INCLUDES) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L./RIoT/RIoTCrypt -lmbedcrypto

EMU_KEYS_CERTS = AliasCert.der AliasCert.pem AliasKey.der AliasKey.pem DeviceIDCrt.der DeviceIDCrt.pem DeviceIDPublic.der DeviceIDPublic.pem R00tCrt.der R00tCrt.pem

# DEBUG
#LOCAL_CFLAGS += -g3 -O0

.SILENT:

.PHONY: all clean

all: riotemulator

riotemulator: lib RIoTEmulator.o
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) RIoTEmulator.o $(LOCAL_LDFLAGS) -o $@

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

lib:
	make -C RIoT

clean:
	rm -f *.o ./RIoT/*.o
	rm -f ./RIoT/RIoTCrypt/*.o ./RIoT/RIoTCrypt/libmbed*
	rm -f ./RIoT/riotester ./riotemulator
	rm -f $(EMU_KEYS_CERTS)

