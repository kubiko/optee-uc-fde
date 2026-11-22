/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <fde_key_handler_ta_type.h>

#define TA_UUID FDE_KEY_HANDLER_UUID_ID

/*
 * Single instance and kept alive, so the measurement register lasts the boot,
 * and kept crashed: a TA that panics is not created again with an empty
 * register, which later code could extend with values it can predict, but
 * fails every call until the reboot.
 *
 * TA_FLAG_INSTANCE_KEEP_CRASHED exists from OP-TEE 4.7, and older OP-TEE
 * rejects a TA with flags it does not know. Without it the TA is built
 * without v2 (FDE_TA_V2 == 0, see fde_key_handler_ta_handle.h), since a
 * normal world that makes the TA panic would get a fresh, unlocked instance.
 */
#if defined(TA_FLAG_INSTANCE_KEEP_CRASHED)
#define TA_FLAGS                    (TA_FLAG_SINGLE_INSTANCE | \
                                     TA_FLAG_MULTI_SESSION | \
                                     TA_FLAG_DEVICE_ENUM | \
                                     TA_FLAG_INSTANCE_KEEP_ALIVE | \
                                     TA_FLAG_INSTANCE_KEEP_CRASHED)
#else
#define TA_FLAGS                    (TA_FLAG_SINGLE_INSTANCE | \
                                     TA_FLAG_MULTI_SESSION | \
                                     TA_FLAG_DEVICE_ENUM | \
                                     TA_FLAG_INSTANCE_KEEP_ALIVE)
#endif
/*
 * RSA key derivation dominates the memory budget: each primality test on a
 * half-key-size candidate drives a modular exponentiation whose window
 * precompute alone can take ~16 KiB of heap for RSA-4096, on top of ~10 KiB
 * of BigInts/export buffers and the transient keypair object.
 */
#define TA_STACK_SIZE               (16 * 1024)
#define TA_DATA_SIZE                (128 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
      "fde key handling via aes" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
