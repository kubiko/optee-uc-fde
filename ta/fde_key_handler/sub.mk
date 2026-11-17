global-incdirs-y += include
global-incdirs-y += .

srcs-y += fde_key_handler_ta_entry.c
srcs-y += fde_key_handler_ta_handle.c
srcs-y += fde_key_handler_ta_v2.c

# A production build, for a device whose RPMB key is provisioned: no usable
# RPMB fails every call that needs the counter, v1 keys included, and v2 keys
# sealed without the counter are refused. See counter_state in fde_key_handler_ta_v2.c.
CFG_FDE_V2_REQUIRE_RPMB ?= n
ifeq ($(CFG_FDE_V2_REQUIRE_RPMB),y)
cflags-fde_key_handler_ta_v2.c-y += -DFDE_V2_REQUIRE_RPMB=1
endif
