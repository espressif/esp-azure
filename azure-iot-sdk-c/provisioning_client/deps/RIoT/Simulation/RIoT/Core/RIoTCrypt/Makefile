
# Also see "include/mbedtls/config.h"

CFLAGS	?= -DRIOTBUILD -DRIOTSECP384R1 -Os
WARNING_CFLAGS ?=  -Wall -Wextra
LDFLAGS ?=

CRYPTO_INCLUDES ?= -I./include -I../include
LOCAL_CFLAGS = $(WARNING_CFLAGS) $(CRYPTO_INCLUDES) -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS =

# DEBUG
#LOCAL_CFLAGS += -g3 -O0

SOEXT_CRYPTO=so.3

# Set AR_DASH= (empty string) to use an ar implementation that does not accept
# the - prefix for command line options (e.g. llvm-ar)
AR_DASH ?= -

ARFLAGS = $(AR_DASH)src

DLEXT ?= so

OBJS_CRYPTO=	aes.o		\
		base64.o	\
		bignum.o	\
		derenc.o	\
		ecdh.o		\
		ecdsa.o		\
		ecp.o		\
		ecp_curves.o	\
		hkdf.o		\
		hmac_drbg.o	\
		md.o		\
		sha1.o		\
		sha256.o	\
		x509bldr.o	\
		platform_util.o	\
		RiotCrypt.o

LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)
OBJS_CRYPTO+=$(THIRDPARTY_CRYPTO_OBJECTS)

.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static
else
all: shared static
endif

static: libmbedcrypto.a

shared: libmbedcrypto.$(DLEXT)

# crypto
libmbedcrypto.a: $(OBJS_CRYPTO)
	echo "  AR    $@"
	$(AR) $(ARFLAGS) $@ $(OBJS_CRYPTO)

libmbedcrypto.$(SOEXT_CRYPTO): $(OBJS_CRYPTO)
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_CRYPTO)

libmbedcrypto.so: libmbedcrypto.$(SOEXT_CRYPTO)
	echo "  LN    $@ -> $<"
	ln -sf $< $@

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o libmbed* $(OBJS_CRYPTO)

