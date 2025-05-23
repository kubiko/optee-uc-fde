# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

include ../../scripts/common.mk
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

ifeq ($(OPTEE_CLIENT_EXPORT),)
$(error TA_DEV_KIT_DIR is not correctly defined)
endif

CC		?= $(CROSS_COMPILE)gcc
CPP		?= $(CROSS_COMPILE)cpp
LD		?= $(CROSS_COMPILE)ld
AR		?= $(CROSS_COMPILE)ar
NM		?= $(CROSS_COMPILE)nm
OBJCOPY		?= $(CROSS_COMPILE)objcopy
OBJDUMP		?= $(CROSS_COMPILE)objdump
READELF		?= $(CROSS_COMPILE)readelf

srcs		:= fde_key_manager_ca.c base64.c
srcs_key	:= $(srcs) fde_key_manager.c
srcs_helper	:= $(srcs) fde_helper.c

objs_key 	:= $(patsubst %.c,$(out-dir)/fde_key_manager/%.o, $(srcs_key))
objs_helper	:= $(patsubst %.c,$(out-dir)/fde_key_manager/%.o, $(srcs_helper))

CFLAGS += -I./

CFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include

CFLAGS += -I../../ta/fde_key_handler/include

TA_DIR ?= /lib/optee_armtz
CFLAGS += -DTA_DIR=\"$(TA_DIR)\"

CFLAGS += -g3

LDFLAGS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec -ljson-c
LDFLAGS += -lpthread -lm

.PHONY: all
all: fde-reveal-key fde-setup fde-key-manager fde-helper

fde-reveal-key: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

fde-setup: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

fde-key-manager: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

fde-helper: $(objs_helper)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS) -lcryptsetup

$(out-dir)/fde_key_manager/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(out-dir)/fde_key_manager
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) -c $< -o $@

RMDIR := rmdir --ignore-fail-on-non-empty
define rm-build-dirs
	$(q)for d in $1; do $(RMDIR) $(out-dir)/fde_key_manager/$$d 2> /dev/null; true; done
	$(q)$(RMDIR) $(out-dir)/fde_key_manager 2> /dev/null; true
	$(q)$(RMDIR) $(out-dir) 2> /dev/null; true
endef

.PHONY: clean
clean:
	@echo '  CLEAN $(out-dir)'
	$(q)rm -rf $(out-dir)/fde_key_manager
	$(q)$(foreach obj,$(objs), rm -f $(obj))
