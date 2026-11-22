global-incdirs-y += include
global-incdirs-y += .

srcs-y += fde_key_handler_ta_entry.c
srcs-y += fde_key_handler_ta_handle.c
srcs-y += fde_key_handler_ta_v2.c

# CFG_FDE_V2_REQUIRE_RPMB=y (default), for a device whose RPMB key is
# provisioned: no usable RPMB fails every call that needs the counter, v1 keys
# included, and v2 keys sealed without the counter are refused.
#
# CFG_FDE_V2_REQUIRE_RPMB=n, only for a development device without a
# provisioned RPMB key: keys seal and unseal without the counter, and a normal
# world that blocks RPMB from the start of the boot downgrades the device to
# that, v1 keys included. See counter_state in fde_key_handler_ta_v2.c.
CFG_FDE_V2_REQUIRE_RPMB ?= y
ifeq ($(CFG_FDE_V2_REQUIRE_RPMB),y)
cflags-fde_key_handler_ta_v2.c-y += -DFDE_V2_REQUIRE_RPMB=1
else ifeq ($(CFG_FDE_V2_REQUIRE_RPMB),n)
cflags-fde_key_handler_ta_v2.c-y += -DFDE_V2_REQUIRE_RPMB=0
$(warning CFG_FDE_V2_REQUIRE_RPMB=n: development build, the RPMB counter can be bypassed)
else
$(error CFG_FDE_V2_REQUIRE_RPMB must be y or n, not '$(CFG_FDE_V2_REQUIRE_RPMB)')
endif
