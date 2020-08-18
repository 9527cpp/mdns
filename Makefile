# COMPILE_PREFIX=arm-anykav200-linux-uclibcgnueabi-
COMPILE_PREFIX=arm-openwrt-linux-muslgnueabi-
# COMPILE_PREFIX=
CC=$(COMPILE_PREFIX)gcc
AR=$(COMPILE_PREFIX)ar
STRIP=$(COMPILE_PREFIX)strip

CFLAGS = -Wall -ffunction-sections -O2 -rdynamic -std=gnu99

CFLAGS_COMMON = -fwrapv -W
CFLAGS_OS = -D_GNU_SOURCE -DNOT_HAVE_SA_LEN -DUSES_NETLINK -DHAVE_LINUX -fno-strict-aliasing -DHAVE_IPV6=0 
CFLAGS_DEBUG = -DMDNS_DEBUGMSGS=0
CFLAGS += $(CFLAGS_COMMON) $(CFLAGS_OS) $(CFLAGS_DEBUG) 

CFLAGS += -DLINUX -I../include 

AFLAGS += -crs

LIB = ../lib/libmdns.a
EXE = ../exe/mdns

SRC := $(wildcard *.c)
OBJS := $(SRC:%.c=%.o)

BUILD_EXE=y
TGT := $(LIB)

ifeq ($(BUILD_EXE),y)
CFLAGS += -DBUILD_EXE
TGT += $(EXE)
endif

all:$(TGT)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(LIB):$(OBJS)
	$(AR) $(AFLAGS) $@ $(LDLIBS) $^

$(EXE):$(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(LIB) *.o
