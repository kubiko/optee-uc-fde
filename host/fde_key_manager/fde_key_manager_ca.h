/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 *
 * Backend interface of the fde key manager.
 *
 * The front-end (fde_key_manager.c) implements the Ubuntu Core FDE hook
 * protocol (fde-setup / fde-reveal-key) and is backend independent. A backend
 * provides the sealing primitives below:
 *   - OP-TEE backend: fde_key_manager_ca.c, talks to the fde_key_handler TA.
 *
 * All functions returning uint32_t return 0 on success and a backend
 * specific non-zero error code on failure.
 */

#ifndef FDE_KEY_MANAGER_H_
#define FDE_KEY_MANAGER_H_

#include <stddef.h>
#include <stdint.h>

#include "fde_key_handler_ta_type.h"

/*
 * Backend provided constants:
 *   MAX_BUF_SIZE: maximum size of a key passed for sealing / unsealing
 *   HANDLE_SIZE:  size of the key handle returned by encrypt_key()
 */

// helper wrapper around mbedtls_base64_encode function
extern char *base64_encode(const unsigned char *in_buf, size_t in_buf_len);
// helper wrapper around mbedtls_base64_decode function
extern unsigned char *base64_decode(const char *in_buf,
                                     size_t in_buf_len, size_t *buf_len);

extern uint32_t encrypt_key(unsigned char *in_buf, size_t in_buf_len,
                            unsigned char *handle, size_t *handle_len,
                            unsigned char *out_buf, size_t *out_buf_len);
extern uint32_t decrypt_key(unsigned char *in_buf, size_t in_buf_len,
                            unsigned char *handle, size_t handle_len,
                            unsigned char *out_buf, size_t *out_buf_len);
extern uint32_t lock_ta(void);
extern uint32_t get_ta_lock(uint32_t *value);
extern unsigned char *generate_rng(size_t buf_len);
extern uint32_t get_ta_version(uint32_t *version);

/*
 * Backend specific out-of-context (testing / provisioning) CLI options.
 * backend_handle_cli() returns 1 if it handled argv[1] (result in *ret),
 * 0 if the option is unknown to the backend.
 */
extern void backend_print_help(void);
extern int backend_handle_cli(int argc, char *argv[], int *ret);

// ree_log helper wrapper
#define REE_ERROR   1
#define REE_WARNING 2
#define REE_INFO    3
#define REE_DEBUG   4
extern void ree_log(int log_level, const char *format, ...);
#endif // FDE_KEY_MANAGER_H_
