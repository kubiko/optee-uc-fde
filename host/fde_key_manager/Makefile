# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.

out-dir := $(abspath $(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

# Sealing backend:
#   optee (default): OP-TEE fde_key_handler TA, needs OPTEE_CLIENT_EXPORT
#   rpi:             Raspberry Pi 4/5 family firmware crypto (OTP device key),
#                    needs libcrypto (OpenSSL) and libjson-c
BACKEND ?= optee

ifeq ($(BACKEND),optee)
ifeq ($(OPTEE_CLIENT_EXPORT),)
$(error OPTEE_CLIENT_EXPORT is not correctly defined)
endif
else ifneq ($(BACKEND),rpi)
$(error unsupported BACKEND=$(BACKEND), use optee or rpi)
endif

CC		?= $(CROSS_COMPILE)gcc
CPP		?= $(CROSS_COMPILE)cpp
LD		?= $(CROSS_COMPILE)ld
AR		?= $(CROSS_COMPILE)ar
NM		?= $(CROSS_COMPILE)nm
OBJCOPY		?= $(CROSS_COMPILE)objcopy
OBJDUMP		?= $(CROSS_COMPILE)objdump
READELF		?= $(CROSS_COMPILE)readelf

srcs		:= fde_key_manager_common.c base64.c
ifeq ($(BACKEND),rpi)
srcs		+= rpi_fde_backend.c
else
srcs		+= fde_key_manager_ca.c
endif
srcs_key	:= $(srcs) fde_key_manager.c

# backend specific object dir: the shared front-end is compiled per backend
objs_key 	:= $(patsubst %.c,$(out-dir)/fde_key_manager/obj-$(BACKEND)/%.o, $(srcs_key))

CFLAGS += -I./

CFLAGS += -g3

ifeq ($(BACKEND),rpi)
CFLAGS += -DFDE_BACKEND_RPI
LDFLAGS += -lcrypto -ljson-c

.PHONY: all
all: fde-reveal-key fde-setup fde-key-manager
else
CFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include

CFLAGS += -I../../ta/fde_key_handler/include

TA_DIR ?= /lib/optee_armtz
CFLAGS += -DTA_DIR=\"$(TA_DIR)\"

LDFLAGS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec -ljson-c
LDFLAGS += -lpthread -lm

.PHONY: all
all: fde-reveal-key fde-setup fde-key-manager
endif

fde-reveal-key: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

fde-setup: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

fde-key-manager: $(objs_key)
	@echo "  LD      $(out-dir)/fde_key_manager/$@"
	$(q)@$(CC) -o $(out-dir)/fde_key_manager/$@ $+ $(LDFLAGS)

$(out-dir)/fde_key_manager/obj-$(BACKEND)/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(out-dir)/fde_key_manager/obj-$(BACKEND)
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
