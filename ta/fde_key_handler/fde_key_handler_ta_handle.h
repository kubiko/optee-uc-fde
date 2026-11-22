/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#ifndef FDE_KEY_HANDLER_TA_HANDLE_H_
#define FDE_KEY_HANDLER_TA_HANDLE_H_

#include <tee_internal_api.h>

/*
 * The GP TEE Internal Core API 1.3.1 changed the type of all buffer length
 * parameters (e.g. TEE_AEEncryptFinal() destLen/tagLen, TEE_MACComputeFinal()
 * macLen, TEE_DigestDoFinal() hashLen, TEE_AsymmetricSignDigest()
 * signatureLen, TEE_GetObjectBufferAttribute() size,
 * TEE_BigIntConvertToOctetString() bufferLen) and of TEE_Param memref.size
 * from uint32_t to size_t. Select a matching local length type so the TA
 * builds against any supported OP-TEE version:
 *   - OP-TEE 3.x (Core API 1.1) expects uint32_t.
 *   - OP-TEE 4.x uses size_t by default; compatibility mode selects the
 *     legacy uint32_t (__GP11) variant.
 * Select size_t only when Core API 1.3.1 or newer is exposed without compat.
 * Use tee_len_t for every variable whose address is passed to the GP API,
 * in every source file of the TA.
 */
#if defined(TEE_CORE_API_VERSION) && TEE_CORE_API_VERSION >= 0x01030100 && \
    defined(__OPTEE_CORE_API_COMPAT_1_1) && \
    !__OPTEE_CORE_API_COMPAT_1_1
typedef size_t tee_len_t;
#else
typedef uint32_t tee_len_t;
#endif

/*
 * v2 (measured boot, RPMB counter, fde_key_handler_ta_v2.c) is only built
 * where OP-TEE keeps a crashed TA crashed (TA_FLAG_INSTANCE_KEEP_CRASHED,
 * OP-TEE 4.7 and newer). Older OP-TEE destroys a TA that panics and creates
 * it again on the next session: the register empty and the lock released.
 * The normal world can make the TA panic at will, e.g. with an RPMB error
 * libutee does not pass on, so v2 there would be weaker than v1. Such a
 * build is v1 only: the v2 commands are not supported, the v1 commands do
 * not touch RPMB, and TA_CMD_TA_VERSION reports FDE_TA_VERSION_V1.
 */
#include <user_ta_header.h>
#if defined(TA_FLAG_INSTANCE_KEEP_CRASHED)
#define FDE_TA_V2 1
#else
#define FDE_TA_V2 0
#endif

#define TA_UNLOCKED  0
#define TA_LOCKED    1

/* =========================================================================
 * Session context
 * ========================================================================= */

typedef struct {
    TEE_ObjectHandle  key_pair;     /* transient keypair – NULL until derived */
    uint32_t          algo;         /* ALGO_RSA | ALGO_ECDSA                  */
    uint32_t          key_bits;     /* e.g. 2048, 256                         */
    bool              key_ready;
} session_ctx_t;


extern TEE_Result cmd_symmetric_key_crypto(TEE_OperationMode mode,
                             unsigned int paramTypes,
                             TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result generate_random(uint32_t types,
                                  TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result get_ta_version(uint32_t types,
                                  TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result derive_ta_unique_key(uint8_t *key, uint16_t key_size,
                                       uint8_t *handle, uint32_t handle_size);

/* v2, fde_key_handler_ta_v2.c */
extern TEE_Result cmd_extend(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_get_register(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_key_encrypt_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_key_decrypt_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_get_counter(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_raise_counter(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result cmd_key_reseal_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]);
extern bool v1_handles_refused(void);

/* Asymetric crypto operations */
extern TEE_Result cmd_asymmetric_derive_keypair(session_ctx_t *ctx,
                                               uint32_t param_types,
                                               TEE_Param params[4]);
extern TEE_Result cmd_asymmetric_sign(session_ctx_t *ctx,
                              uint32_t param_types,
                              TEE_Param params[4]);

extern TEE_Result cmd_asymmetric_decrypt(session_ctx_t *ctx,
                                 uint32_t param_types,
                                 TEE_Param params[4]);
extern TEE_Result cmd_asymmetric_get_pubkey(session_ctx_t *ctx,
                                    uint32_t param_types,
                                    TEE_Param params[4]);
#endif
