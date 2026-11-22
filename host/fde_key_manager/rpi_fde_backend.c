/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 *
 * Raspberry Pi backend of the fde key manager.
 *
 * Supported boards: Raspberry Pi 4 / CM4 / Pi 400 (BCM2711) and
 * Raspberry Pi 5 / CM5 / Pi 500 (BCM2712).
 *
 * There is no OP-TEE on these boards; the secure storage used instead is the
 * device unique OTP private key, accessed through the VideoCore firmware
 * crypto service ("rpifwcrypto", mailbox property interface). The firmware
 * computes HMAC-SHA256 keyed with the OTP key, so with
 * `lock_device_private_key=1` in config.txt the raw OTP key never becomes
 * visible to Linux.
 *
 * Sealing scheme (see rpi_fde_backend.h for the handle layout):
 *
 *   nonce, iv     = random
 *   wrap_key      = HMAC-SHA256(OTP key, RPI_KDF_LABEL || nonce)   [firmware]
 *   sealed, tag   = AES-256-GCM(wrap_key, iv, aad = version||nonce||iv, key)
 *
 * 'lock' maps to the firmware per-key READ_LOCKED | HMAC_LOCKED status: once
 * set, the wrapping key cannot be derived again until the next reboot, which
 * mirrors the TA_CMD_LOCK semantics of the OP-TEE backend.
 *
 * Requirements:
 *   - firmware with the crypto service: start4.elf (Pi 4 family) or bootloader
 *     EEPROM (Pi 5 family) with rpifwcrypto support; per-key locking needs
 *     2026-06 or newer firmware
 *   - provisioned OTP device key (see --provision-otp-key)
 *   - /dev/vcio_crypto or /dev/vcio (snap hook: `vcio` interface)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/random.h>

#include <openssl/evp.h>

#include "fde_key_manager_ca.h"

/* ------------------------------------------------------------------------
 * VideoCore mailbox property interface
 * ------------------------------------------------------------------------ */

#define VCIO_IOC_MAGIC          100
#define IOCTL_MBOX_PROPERTY     _IOWR(VCIO_IOC_MAGIC, 0, char *)

#define VC_MBOX_PROCESS_REQUEST 0x00000000
#define VC_MBOX_STATUS_SUCCESS  0x80000000  /* 0x80000001: request failed */
#define VC_MBOX_RESPONSE_BIT    0x80000000
#define VC_MBOX_ERROR_BIT       0x80000000

#define TAG_GET_CRYPTO_LAST_ERROR     0x0003008e
#define TAG_GET_CRYPTO_NUM_OTP_KEYS   0x0003008f
#define TAG_GET_CRYPTO_KEY_STATUS     0x00030090
#define TAG_SET_CRYPTO_KEY_STATUS     0x00038090
#define TAG_GET_CRYPTO_HMAC_SHA256    0x00030092
#define TAG_GET_CRYPTO_GEN_ECDSA_KEY  0x00030095

/* key status bits */
#define KEY_STATUS_DEVICE_PRIVATE_KEY (1u << 0)
#define KEY_STATUS_READ_LOCKED        (1u << 8)
#define KEY_STATUS_GEN_LOCKED         (1u << 9)
#define KEY_STATUS_SIGN_LOCKED        (1u << 10)
#define KEY_STATUS_HMAC_LOCKED        (1u << 11)
#define KEY_STATUS_USAGE_LOCKED       (1u << 12)

#define FDE_LOCK_STATUS (KEY_STATUS_READ_LOCKED | KEY_STATUS_HMAC_LOCKED)

/* firmware crypto error codes (TAG_GET_CRYPTO_LAST_ERROR) */
enum {
    FW_CRYPTO_SUCCESS = 0,
    FW_CRYPTO_ERROR_UNKNOWN = 1,
    FW_CRYPTO_EINVAL = 2,
    FW_CRYPTO_KEY_NOT_FOUND = 3,
    FW_CRYPTO_KEY_LOCKED = 4,
    FW_CRYPTO_KEY_OTP_ERROR = 5,
    FW_CRYPTO_KEY_NOT_SET = 6,
    FW_CRYPTO_KEY_INVALID = 7,
    FW_CRYPTO_NOT_SUPPORTED = 8,
    FW_CRYPTO_OPERATION_FAILED = 9,
    FW_CRYPTO_KEY_NOT_BLANK = 10,
};

#define FW_HMAC_MSG_MAX_SIZE 2048
#define FW_HMAC_SIZE         32

struct mbox_hdr {
    uint32_t buf_size;
    uint32_t code;
    uint32_t tag;
    uint32_t tag_buf_size;
    uint32_t tag_req_resp_size;
};

struct mbox_value_msg {
    struct mbox_hdr hdr;
    uint32_t value[4];
    uint32_t end_tag;
} __attribute__((aligned(16)));

struct mbox_hmac_msg {
    struct mbox_hdr hdr;
    union {
        struct {
            uint32_t flags;
            uint32_t key_id;
            uint32_t length;
            uint8_t message[FW_HMAC_MSG_MAX_SIZE];
        } req;
        struct {
            uint32_t status;
            uint32_t length;
            uint8_t hmac[FW_HMAC_SIZE];
        } resp;
    };
    uint32_t end_tag;
} __attribute__((aligned(16)));

/* Error codes returned by this backend (front-end prints them as hex) */
#define RPI_ERR_BASE            0xF0D00000u
#define RPI_ERR_GENERIC         (RPI_ERR_BASE | 0x01)
#define RPI_ERR_BAD_PARAMETERS  (RPI_ERR_BASE | 0x02)
#define RPI_ERR_SHORT_BUFFER    (RPI_ERR_BASE | 0x03)
#define RPI_ERR_NO_DEVICE       (RPI_ERR_BASE | 0x04)
#define RPI_ERR_MAILBOX         (RPI_ERR_BASE | 0x05)
#define RPI_ERR_RNG             (RPI_ERR_BASE | 0x06)
#define RPI_ERR_CRYPTO          (RPI_ERR_BASE | 0x07)
#define RPI_ERR_AUTH            (RPI_ERR_BASE | 0x08)
/* firmware crypto errors are reported as RPI_ERR_FW_BASE | fw error code */
#define RPI_ERR_FW_BASE         (RPI_ERR_BASE | 0x100)

/* Wrapping key derivation label, versioned with the handle format */
static const char RPI_KDF_LABEL[] = "ubuntu-core-fde:rpi:wrap-key:v1";

static const char *fw_strerror(uint32_t code) {
    switch (code) {
        case FW_CRYPTO_SUCCESS:          return "success";
        case FW_CRYPTO_ERROR_UNKNOWN:    return "unknown error";
        case FW_CRYPTO_EINVAL:           return "invalid argument";
        case FW_CRYPTO_KEY_NOT_FOUND:    return "key not found";
        case FW_CRYPTO_KEY_LOCKED:       return "key locked";
        case FW_CRYPTO_KEY_OTP_ERROR:    return "OTP read error";
        case FW_CRYPTO_KEY_NOT_SET:      return "key not provisioned (all zeros)";
        case FW_CRYPTO_KEY_INVALID:      return "invalid key";
        case FW_CRYPTO_NOT_SUPPORTED:    return "operation not supported";
        case FW_CRYPTO_OPERATION_FAILED: return "operation failed";
        case FW_CRYPTO_KEY_NOT_BLANK:    return "key slot not blank";
        default:                         return "unrecognised error";
    }
}

static int mbox_open(void) {
    /* prefer the restricted crypto-only interface when the kernel has it */
    static const char *devices[] = { "/dev/vcio_crypto", "/dev/vcio" };
    size_t i;
    int fd;

    for (i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        fd = open(devices[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0)
            return fd;
    }
    ree_log(REE_ERROR, "rpi: cannot open /dev/vcio_crypto or /dev/vcio: %s",
            strerror(errno));
    return -1;
}

/*
 * Send one property tag message. Returns 0 if the firmware processed the
 * request successfully and handled the tag, RPI_ERR_* otherwise.
 *
 * The kernel vcio driver already turns a request status other than
 * VC_MBOX_STATUS_SUCCESS into an ioctl error; check it here too so a
 * failed request is never taken for success.
 */
static uint32_t mbox_call(void *msg, uint32_t buf_size) {
    struct mbox_hdr *hdr = msg;
    int fd;
    int rc;

    hdr->buf_size = buf_size;
    hdr->code = VC_MBOX_PROCESS_REQUEST;

    fd = mbox_open();
    if (fd < 0)
        return RPI_ERR_NO_DEVICE;

    rc = ioctl(fd, IOCTL_MBOX_PROPERTY, msg);
    close(fd);
    if (rc < 0) {
        ree_log(REE_ERROR, "rpi: mailbox tag 0x%08x ioctl failed: %s",
                hdr->tag, strerror(errno));
        return RPI_ERR_MAILBOX;
    }
    if (hdr->code != VC_MBOX_STATUS_SUCCESS ||
        !(hdr->tag_req_resp_size & VC_MBOX_RESPONSE_BIT)) {
        ree_log(REE_DEBUG, "rpi: mailbox tag 0x%08x not handled "
                "(code 0x%08x, resp 0x%08x)", hdr->tag, hdr->code,
                hdr->tag_req_resp_size);
        return RPI_ERR_MAILBOX;
    }
    return 0;
}

/* Firmware crypto last error, FW_CRYPTO_ERROR_UNKNOWN if not retrievable */
static uint32_t fw_last_error(void) {
    struct mbox_value_msg msg;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.tag = TAG_GET_CRYPTO_LAST_ERROR;
    msg.hdr.tag_buf_size = sizeof(msg.value);
    if (mbox_call(&msg, sizeof(msg)))
        return FW_CRYPTO_ERROR_UNKNOWN;
    return msg.value[0];
}

/* Convert a failed firmware crypto request into a logged RPI_ERR_* code */
static uint32_t fw_error(const char *what, uint32_t mbox_res) {
    uint32_t fw_err;

    if (mbox_res == RPI_ERR_NO_DEVICE)
        return mbox_res;
    fw_err = fw_last_error();
    ree_log(REE_ERROR, "rpi: firmware %s failed: %s (%u)", what,
            fw_strerror(fw_err), fw_err);
    if (fw_err == FW_CRYPTO_SUCCESS || fw_err == FW_CRYPTO_ERROR_UNKNOWN)
        return mbox_res ? mbox_res : RPI_ERR_GENERIC;
    return RPI_ERR_FW_BASE | fw_err;
}

static uint32_t fw_get_num_otp_keys(uint32_t *num) {
    struct mbox_value_msg msg;
    uint32_t res;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.tag = TAG_GET_CRYPTO_NUM_OTP_KEYS;
    msg.hdr.tag_buf_size = sizeof(msg.value);
    res = mbox_call(&msg, sizeof(msg));
    if (res)
        return res;
    *num = msg.value[0];
    return 0;
}

static uint32_t fw_get_key_status(uint32_t key_id, uint32_t *status) {
    struct mbox_value_msg msg;
    uint32_t res;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.tag = TAG_GET_CRYPTO_KEY_STATUS;
    msg.hdr.tag_buf_size = sizeof(msg.value);
    msg.value[0] = key_id;
    res = mbox_call(&msg, sizeof(msg));
    if (res)
        return res;
    if (msg.value[0] & VC_MBOX_ERROR_BIT)
        return RPI_ERR_FW_BASE | FW_CRYPTO_KEY_NOT_FOUND;
    *status = msg.value[0];
    return 0;
}

static uint32_t fw_set_key_status(uint32_t key_id, uint32_t status) {
    struct mbox_value_msg msg;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.tag = TAG_SET_CRYPTO_KEY_STATUS;
    msg.hdr.tag_buf_size = sizeof(msg.value);
    msg.value[0] = key_id;
    msg.value[1] = status;
    return mbox_call(&msg, sizeof(msg));
}

static uint32_t fw_gen_ecdsa_key(uint32_t key_id) {
    struct mbox_value_msg msg;
    uint32_t res;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.tag = TAG_GET_CRYPTO_GEN_ECDSA_KEY;
    msg.hdr.tag_buf_size = sizeof(msg.value);
    msg.value[0] = 0;       /* flags */
    msg.value[1] = key_id;
    res = mbox_call(&msg, sizeof(msg));
    if (res)
        return fw_error("OTP key generation", res);
    return 0;
}

/* HMAC-SHA256(OTP key[key_id], message), computed by the firmware */
static uint32_t fw_hmac_sha256(uint32_t key_id,
                               const uint8_t *message, size_t message_len,
                               uint8_t hmac[FW_HMAC_SIZE]) {
    struct mbox_hmac_msg *msg;
    uint32_t res;

    if (!message || !message_len || message_len > FW_HMAC_MSG_MAX_SIZE)
        return RPI_ERR_BAD_PARAMETERS;

    /* ~2KiB, keep it off the stack */
    msg = aligned_alloc(16, sizeof(*msg));
    if (!msg)
        return RPI_ERR_GENERIC;
    memset(msg, 0, sizeof(*msg));

    msg->hdr.tag = TAG_GET_CRYPTO_HMAC_SHA256;
    msg->hdr.tag_buf_size = sizeof(msg->req);
    msg->req.flags = 0;
    msg->req.key_id = key_id;
    msg->req.length = (uint32_t)message_len;
    memcpy(msg->req.message, message, message_len);

    res = mbox_call(msg, sizeof(*msg));
    if (!res && ((msg->resp.status & VC_MBOX_ERROR_BIT) ||
                 msg->resp.length != FW_HMAC_SIZE))
        res = RPI_ERR_GENERIC;

    if (res) {
        res = fw_error("HMAC", res);
    } else {
        memcpy(hmac, msg->resp.hmac, FW_HMAC_SIZE);
    }

    explicit_bzero(msg, sizeof(*msg));
    free(msg);
    return res;
}

/* ------------------------------------------------------------------------
 * Sealing helpers
 * ------------------------------------------------------------------------ */

static uint32_t get_random(uint8_t *buf, size_t len) {
    size_t done = 0;
    ssize_t r;

    while (done < len) {
        r = getrandom(buf + done, len - done, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            ree_log(REE_ERROR, "rpi: getrandom failed: %s", strerror(errno));
            return RPI_ERR_RNG;
        }
        done += (size_t)r;
    }
    return 0;
}

/* wrap_key = HMAC-SHA256(OTP key, RPI_KDF_LABEL || nonce) */
static uint32_t derive_wrap_key(const uint8_t nonce[RPI_NONCE_SIZE],
                                uint8_t wrap_key[FW_HMAC_SIZE]) {
    uint8_t msg[sizeof(RPI_KDF_LABEL) - 1 + RPI_NONCE_SIZE];
    uint32_t res;

    memcpy(msg, RPI_KDF_LABEL, sizeof(RPI_KDF_LABEL) - 1);
    memcpy(msg + sizeof(RPI_KDF_LABEL) - 1, nonce, RPI_NONCE_SIZE);
    res = fw_hmac_sha256(RPI_FDE_OTP_KEY_ID, msg, sizeof(msg), wrap_key);
    explicit_bzero(msg, sizeof(msg));
    if (res == (RPI_ERR_FW_BASE | FW_CRYPTO_KEY_LOCKED))
        ree_log(REE_ERROR, "rpi: OTP key is locked until next reboot");
    else if (res == (RPI_ERR_FW_BASE | FW_CRYPTO_KEY_NOT_SET))
        ree_log(REE_ERROR, "rpi: OTP device key is not provisioned, see "
                "--provision-otp-key");
    return res;
}

/* handle field offsets */
#define H_VERSION   0
#define H_NONCE     (H_VERSION + 1)
#define H_IV        (H_NONCE + RPI_NONCE_SIZE)
#define H_TAG       (H_IV + RPI_IV_SIZE)
#define H_AAD_LEN   H_TAG

static uint32_t aes_gcm(int encrypt, const uint8_t key[FW_HMAC_SIZE],
                        uint8_t *handle,
                        const uint8_t *in, size_t in_len, uint8_t *out) {
    EVP_CIPHER_CTX *ctx;
    uint32_t res = RPI_ERR_CRYPTO;
    int len = 0;
    int fin = 0;

    if (in_len > MAX_BUF_SIZE)
        return RPI_ERR_BAD_PARAMETERS;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return RPI_ERR_CRYPTO;

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL,
                          encrypt) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, RPI_IV_SIZE,
                            NULL) != 1)
        goto out;
    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, handle + H_IV,
                          encrypt) != 1)
        goto out;
    /* authenticate version || nonce || iv */
    if (EVP_CipherUpdate(ctx, NULL, &len, handle, H_AAD_LEN) != 1)
        goto out;
    if (EVP_CipherUpdate(ctx, out, &len, in, (int)in_len) != 1 ||
        (size_t)len != in_len)
        goto out;
    if (!encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, RPI_TAG_SIZE,
                            handle + H_TAG) != 1)
        goto out;
    if (EVP_CipherFinal_ex(ctx, out + len, &fin) != 1 || fin != 0) {
        res = encrypt ? RPI_ERR_CRYPTO : RPI_ERR_AUTH;
        goto out;
    }
    if (encrypt &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, RPI_TAG_SIZE,
                            handle + H_TAG) != 1)
        goto out;
    res = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    if (res)
        explicit_bzero(out, in_len);
    return res;
}

/* Warn when the raw OTP key is still readable from Linux */
static void check_key_read_lock(void) {
    uint32_t status = 0;

    if (fw_get_key_status(RPI_FDE_OTP_KEY_ID, &status)) {
        ree_log(REE_WARNING, "rpi: WARNING: firmware does not report OTP key "
                "status; 'lock' will not be able to protect the sealed keys "
                "after boot. Update the firmware.");
        return;
    }
    if (!(status & KEY_STATUS_READ_LOCKED))
        ree_log(REE_WARNING, "rpi: WARNING: raw OTP device key is readable, "
                "set lock_device_private_key=1 in config.txt");
}

/* ------------------------------------------------------------------------
 * Backend interface
 * ------------------------------------------------------------------------ */

uint32_t encrypt_key(unsigned char *in_buf, size_t in_buf_len,
                     unsigned char *handle, size_t *handle_len,
                     unsigned char *out_buf, size_t *out_buf_len) {
    uint8_t wrap_key[FW_HMAC_SIZE];
    uint8_t h[HANDLE_SIZE];
    uint32_t res;

    if (!in_buf || !in_buf_len || in_buf_len > MAX_BUF_SIZE ||
        !handle || !handle_len || !out_buf || !out_buf_len)
        return RPI_ERR_BAD_PARAMETERS;
    if (*handle_len < HANDLE_SIZE || *out_buf_len < in_buf_len)
        return RPI_ERR_SHORT_BUFFER;

    check_key_read_lock();

    h[H_VERSION] = RPI_HANDLE_VERSION;
    res = get_random(h + H_NONCE, RPI_NONCE_SIZE + RPI_IV_SIZE);
    if (res)
        return res;

    res = derive_wrap_key(h + H_NONCE, wrap_key);
    if (res)
        goto out;

    res = aes_gcm(1, wrap_key, h, in_buf, in_buf_len, out_buf);
    if (res)
        goto out;

    memcpy(handle, h, HANDLE_SIZE);
    *handle_len = HANDLE_SIZE;
    *out_buf_len = in_buf_len;

out:
    explicit_bzero(wrap_key, sizeof(wrap_key));
    return res;
}

uint32_t decrypt_key(unsigned char *in_buf, size_t in_buf_len,
                     unsigned char *handle, size_t handle_len,
                     unsigned char *out_buf, size_t *out_buf_len) {
    uint8_t wrap_key[FW_HMAC_SIZE];
    uint8_t h[HANDLE_SIZE];
    uint32_t res;

    if (!in_buf || !in_buf_len || in_buf_len > MAX_BUF_SIZE ||
        !handle || !out_buf || !out_buf_len)
        return RPI_ERR_BAD_PARAMETERS;
    if (handle_len != HANDLE_SIZE) {
        ree_log(REE_ERROR, "rpi: bad handle size %zu", handle_len);
        return RPI_ERR_BAD_PARAMETERS;
    }
    if (handle[H_VERSION] != RPI_HANDLE_VERSION) {
        ree_log(REE_ERROR, "rpi: bad handle version 0x%02x",
                handle[H_VERSION]);
        return RPI_ERR_BAD_PARAMETERS;
    }
    if (*out_buf_len < in_buf_len)
        return RPI_ERR_SHORT_BUFFER;

    /* work on a copy, aes_gcm() takes a mutable handle for the encrypt case */
    memcpy(h, handle, HANDLE_SIZE);

    res = derive_wrap_key(h + H_NONCE, wrap_key);
    if (res)
        goto out;

    res = aes_gcm(0, wrap_key, h, in_buf, in_buf_len, out_buf);
    if (res) {
        if (res == RPI_ERR_AUTH)
            ree_log(REE_ERROR, "rpi: sealed key authentication failed");
        goto out;
    }
    *out_buf_len = in_buf_len;

out:
    explicit_bzero(wrap_key, sizeof(wrap_key));
    return res;
}

/*
 * Lock the OTP key (raw read and HMAC) until next reboot, so the wrapping
 * keys cannot be re-derived once the initrd is done.
 *
 * Firmware without per-key locking cannot provide this guarantee; per
 * platform policy this is reported as a warning and does not fail the boot.
 */
uint32_t lock_ta(void) {
    uint32_t status = 0;
    uint32_t res;

    res = fw_set_key_status(RPI_FDE_OTP_KEY_ID, FDE_LOCK_STATUS);
    if (!res)
        res = fw_get_key_status(RPI_FDE_OTP_KEY_ID, &status);
    if (!res && (status & FDE_LOCK_STATUS) != FDE_LOCK_STATUS)
        res = RPI_ERR_GENERIC;

    if (res) {
        ree_log(REE_WARNING, "rpi: WARNING: cannot lock OTP key (0x%x, status "
                "0x%08x): firmware lacks per-key locking, sealed keys remain "
                "unsealable until reboot. Update the firmware.", res, status);
        return 0;
    }
    ree_log(REE_INFO, "rpi: OTP key locked until next reboot");
    return 0;
}

uint32_t get_ta_lock(uint32_t *value) {
    uint32_t status = 0;
    uint32_t res;

    if (!value)
        return RPI_ERR_BAD_PARAMETERS;
    res = fw_get_key_status(RPI_FDE_OTP_KEY_ID, &status);
    if (res)
        return res;
    *value = (status & KEY_STATUS_HMAC_LOCKED) ? 1 : 0;
    return 0;
}

unsigned char *generate_rng(size_t len) {
    unsigned char *buf;

    if (!len)
        return NULL;
    buf = malloc(len);
    if (!buf) {
        ree_log(REE_ERROR, "rpi: rng buf alloc failed");
        return NULL;
    }
    if (get_random(buf, len)) {
        free(buf);
        return NULL;
    }
    return buf;
}

uint32_t get_ta_version(uint32_t *version) {
    if (!version)
        return RPI_ERR_BAD_PARAMETERS;
    *version = RPI_FDE_BACKEND_VERSION;
    return 0;
}

/* ------------------------------------------------------------------------
 * Backend specific CLI
 * ------------------------------------------------------------------------ */

#define CLI_PROVISION         "--provision-otp-key"
#define CLI_PROVISION_CONFIRM "--i-understand-this-burns-otp"
#define CLI_STATUS            "--otp-key-status"

void backend_print_help(void) {
    printf("\nRaspberry Pi backend options:\n");
    printf("\t" CLI_STATUS ": print OTP device key status\n");
    printf("\t" CLI_PROVISION " " CLI_PROVISION_CONFIRM ": generate the OTP "
           "device key (key-id %d)\n", RPI_FDE_OTP_KEY_ID);
    printf("\t\tin firmware. IRREVERSIBLE: permanently programs OTP. Only "
           "works on a blank key slot.\n");
}

static int cli_key_status(void) {
    uint32_t num = 0, status = 0, res;

    res = fw_get_num_otp_keys(&num);
    if (res) {
        printf("Firmware crypto service not available (0x%x)\n", res);
        return EXIT_FAILURE;
    }
    printf("OTP keys: %u\n", num);
    res = fw_get_key_status(RPI_FDE_OTP_KEY_ID, &status);
    if (res) {
        printf("Key %d status: unavailable (0x%x)\n", RPI_FDE_OTP_KEY_ID, res);
        return EXIT_FAILURE;
    }
    printf("Key %d status: 0x%08x%s%s%s%s%s%s\n", RPI_FDE_OTP_KEY_ID, status,
           (status & KEY_STATUS_DEVICE_PRIVATE_KEY) ? " DEVICE_PRIVATE_KEY" : "",
           (status & KEY_STATUS_READ_LOCKED)  ? " READ_LOCKED" : "",
           (status & KEY_STATUS_GEN_LOCKED)   ? " GEN_LOCKED" : "",
           (status & KEY_STATUS_SIGN_LOCKED)  ? " SIGN_LOCKED" : "",
           (status & KEY_STATUS_HMAC_LOCKED)  ? " HMAC_LOCKED" : "",
           (status & KEY_STATUS_USAGE_LOCKED) ? " USAGE_LOCKED" : "");
    return EXIT_SUCCESS;
}

static int cli_provision(int argc, char *argv[]) {
    uint32_t res;

    if (argc < 3 || strcmp(argv[2], CLI_PROVISION_CONFIRM)) {
        printf("Refusing to program OTP without " CLI_PROVISION_CONFIRM "\n");
        return EXIT_FAILURE;
    }
    res = fw_gen_ecdsa_key(RPI_FDE_OTP_KEY_ID);
    if (res) {
        printf("OTP key generation failed (0x%x)\n", res);
        return EXIT_FAILURE;
    }
    printf("OTP device key %d generated\n", RPI_FDE_OTP_KEY_ID);
    return EXIT_SUCCESS;
}

int backend_handle_cli(int argc, char *argv[], int *ret) {
    if (!strcmp(CLI_STATUS, argv[1])) {
        *ret = cli_key_status();
        return 1;
    }
    if (!strcmp(CLI_PROVISION, argv[1])) {
        *ret = cli_provision(argc, argv);
        return 1;
    }
    return 0;
}
