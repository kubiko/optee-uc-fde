/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 *
 * LD_PRELOAD emulation of the Raspberry Pi firmware crypto mailbox
 * (/dev/vcio, rpifwcrypto tags) used to test the rpi fde backend without
 * hardware. Emulates a fixed OTP key, per-key lock status persisted in
 * $MOCK_STATE (removing/resetting it emulates a reboot) and:
 *   MOCK_KEY_BLANK=1        OTP key slot not provisioned
 *   MOCK_NO_LOCK=1          firmware without per-key status/locking
 *   MOCK_NO_KERNEL_CHECK=1  do not emulate the kernel turning a failed
 *                           request status into an ioctl error
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <openssl/hmac.h>

#define IOCTL_MBOX_PROPERTY _IOWR(100, 0, char *)
static int mock_fd = -1;
/* fixed "OTP key" (32 bytes) */
static const uint8_t otp_key[32] = {
  0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
static uint32_t last_err;

static const char *st_path(void) { const char *p = getenv("MOCK_STATE"); return p ? p : "/tmp/vcio-mock-state"; }
static uint32_t load_status(void) { FILE *f = fopen(st_path(), "r"); uint32_t s = 1; if (f) { if (fscanf(f, "%x", &s) != 1) s = 1; fclose(f);} return s; }
static void save_status(uint32_t s) { FILE *f = fopen(st_path(), "w"); if (f) { fprintf(f, "%x\n", s); fclose(f);} }

int open(const char *path, int flags, ...) {
    static int (*real_open)(const char *, int, ...);
    mode_t mode = 0;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    if (!strcmp(path, "/dev/vcio_crypto")) { errno = ENOENT; return -1; }
    if (!strcmp(path, "/dev/vcio")) { mock_fd = real_open("/dev/null", O_RDONLY); return mock_fd; }
    return real_open(path, flags, mode);
}

struct hdr { uint32_t buf_size, code, tag, tag_buf_size, tag_req_resp_size; };

int ioctl(int fd, unsigned long req, ...) {
    static int (*real_ioctl)(int, unsigned long, ...);
    va_list ap; void *arg;
    va_start(ap, req); arg = va_arg(ap, void *); va_end(ap);
    if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    if (fd != mock_fd || req != IOCTL_MBOX_PROPERTY) return real_ioctl(fd, req, arg);

    struct hdr *h = arg; uint32_t *v = (uint32_t *)(h + 1);
    int blank = getenv("MOCK_KEY_BLANK") != NULL;
    int nolock = getenv("MOCK_NO_LOCK") != NULL;
    uint32_t st = load_status();
    h->code = 0x80000000; h->tag_req_resp_size = 0x80000000;
    switch (h->tag) {
    case 0x0003008e: v[0] = last_err; break;
    case 0x0003008f: v[0] = 1; break;
    case 0x00030090: if (nolock) { h->tag_req_resp_size = 0; last_err = 8; break; } v[0] = st; break;
    case 0x00038090: if (nolock) { h->tag_req_resp_size = 0; last_err = 8; break; } save_status(st | v[1]); break;
    case 0x00030095: if (!blank) { h->code = 0x80000001; last_err = 10; } break;
    case 0x00030092: {
        uint32_t len = v[2]; uint8_t *msg = (uint8_t *)&v[3]; unsigned int olen = 32; uint8_t out[32];
        if (blank) { h->code = 0x80000001; last_err = 6; break; }
        if (st & (1u << 11)) { h->code = 0x80000001; last_err = 4; break; }
        if (getenv("MOCK_LOG")) { fprintf(stderr, "[mock] hmac len=%u\n", len); }
        HMAC(EVP_sha256(), otp_key, 32, msg, len, out, &olen);
        v[0] = 0; v[1] = 32; memcpy(&v[2], out, 32); last_err = 0; break; }
    default: h->tag_req_resp_size = 0; break;
    }
    /* like rpi_firmware_property_list(): failed request -> -EINVAL */
    if (h->code != 0x80000000 && !getenv("MOCK_NO_KERNEL_CHECK")) { errno = EINVAL; return -1; }
    return 0;
}
