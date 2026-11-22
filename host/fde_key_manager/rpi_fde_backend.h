/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 *
 * Raspberry Pi (Pi 4 / CM4 / Pi 400 / Pi 5 / CM5 / Pi 500) backend of the
 * fde key manager.
 */

#ifndef RPI_FDE_BACKEND_H_
#define RPI_FDE_BACKEND_H_

/*
 * Key handle layout (all fields fixed size, stored verbatim by snapd):
 *
 *   version(1) || nonce(32) || iv(12) || tag(16)
 *
 * - version: RPI_HANDLE_VERSION, identifies the sealing scheme
 * - nonce:   random, diversifies the firmware derived wrapping key
 * - iv:      random AES-256-GCM IV
 * - tag:     AES-256-GCM authentication tag
 *
 * version || nonce || iv is authenticated as GCM additional data.
 */
#define RPI_HANDLE_VERSION      'P'
#define RPI_NONCE_SIZE          32
#define RPI_IV_SIZE             12
#define RPI_TAG_SIZE            16
#define HANDLE_SIZE             (1 + RPI_NONCE_SIZE + RPI_IV_SIZE + RPI_TAG_SIZE)

/* maximum size of the key being sealed / unsealed */
#define MAX_BUF_SIZE            512

/*
 * OTP key slot used for the wrapping key derivation. Key id 1 is the device
 * unique OTP private key present on all supported boards.
 */
#ifndef RPI_FDE_OTP_KEY_ID
#define RPI_FDE_OTP_KEY_ID      1
#endif

/* Version reported by --get-ta-version for this backend */
#define RPI_FDE_BACKEND_VERSION 0x52500001  /* 'R' 'P' v1 */

#endif // RPI_FDE_BACKEND_H_
