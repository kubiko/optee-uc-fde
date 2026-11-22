/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 *
 * Backend independent helpers shared by all fde_key_manager backends.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "fde_key_manager_ca.h"

// debug log definition
#define REE_LOG_LEVEL REE_DEBUG

// helper wrapper around mbedtls_base64_encode function
char *base64_encode(const unsigned char *in_buf, size_t in_buf_len) {
    int ret = EXIT_SUCCESS;
    size_t base64_len = 0;
    char *encoded_buffer = NULL;

    /* Probe for required output length */
    mbedtls_base64_encode(NULL, 0, &base64_len, in_buf, in_buf_len);

    encoded_buffer = (char *)malloc(base64_len + 1);
    if (!encoded_buffer) {
        ree_log(REE_ERROR, "base64_encode failed to alloc buffer");
        return NULL;
    }
    ret = mbedtls_base64_encode((unsigned char *)encoded_buffer,
                                base64_len + 1,
                                &base64_len,
                                in_buf,
                                in_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "base64_encode failed with: 0x%x", ret);
        free(encoded_buffer);
        return NULL;
    }
    encoded_buffer[base64_len] = '\0';
    return encoded_buffer;
}

// helper wrapper around mbedtls_base64_decode function
unsigned char *base64_decode(const char *in_buf, size_t in_buf_len, size_t *buf_len) {
    int ret = EXIT_SUCCESS;
    size_t needed = 0;
    unsigned char *decoded_buffer = NULL;

    if (strlen(in_buf) != in_buf_len) {
        ree_log(REE_ERROR, "base64_decode: string lengths do not align");
        return NULL;
    }

    /* Probe for required output length */
    mbedtls_base64_decode(NULL, 0, &needed,
                          (const unsigned char *)in_buf, in_buf_len);
    if (needed == 0)
        needed = 1;

    decoded_buffer = (unsigned char *)malloc(needed);
    if (!decoded_buffer) {
        ree_log(REE_ERROR, "base64_decode failed alloc");
        return NULL;
    }
    ret = mbedtls_base64_decode(decoded_buffer,
                                needed,
                                buf_len,
                                (const unsigned char *)in_buf,
                                in_buf_len);
    if (ret) {
        ree_log(REE_ERROR, "base64_decode failed with: 0x%x", ret);
        free(decoded_buffer);
        return NULL;
    }
    return decoded_buffer;
}

void ree_log(int log_level, const char *format, ...) {
    va_list args;
    char buf[2048];

    if(log_level > REE_LOG_LEVEL) {
        return;
    }
    va_start (args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
}
