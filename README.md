# optee TA and REE application to support fde on Ubuntu Core

This repository contains the REE/host and TA to handle sealing and unsealing
of the keys used for the fde on Ubuntu Core systems [2].
Host application is expected to be invoked by snapd/snap bootstrap
within Ubuntu Core runtime.
REE application assumes tee kernel driver is either already loaded
or statically built into the kernel.
Passed keys are encrypted with HUK derived key. Each TA has own derived key,
which is further derived by randomised handle generated at key sealing.

REE application and TA assume optee version 3.12+  [1]

There 3 scenarios for host binary to be executed in.

## During system install: executable `fde-setup`
This hook can be executed either as kernel snap hook in snap environment or
as hook within initramfs runtime.
When running as kernel snap hook, operation to be performed is requested
from`snapctl` with parameter `fde-setup-request`. Returned request is json
formatted string. Result of the operation is passed back to `snapctl` as json
formatted sting with parameter `fde-setup-result`.
When running within initramfs runtime. Operation to be performed is passed as
json formatted string on stdin. Result of the operation is returned
as json formatted string on stdout.
* supported operations:
  * initial-setup: encrypt passed key, generate handle is supported.
    * request: `{"op": "initial-setup","key": "base64-encoded-bytes",
                     "key-name" : "string"}`
    * result: `{"encrypted-key": "base64-encoded-bytes",
               "handle": "<base64-generated-bytes>"}`

## Within initrd: executable `fde-reveal-key`
Operation to be performed is passed as json formatted string on stdin. Result
of the operation is returned as json formatted string on stdout.
* supported operations:
  * reveal: reveal key from passed
    * request: `{ "op": "reveal", "sealed-key": "base64-encoded-bytes",
                 "handle": "base64-encoded-bytes", "sealed-key-name": "string"}`
    * result: `{"key": "base64 encoded key"}`
  * lock: lock interface till next reboot
    * request: `{ "op": "lock" }`
    * result:

## Testing
* --ta-lock-status: get TA lock status
* --lock-ta: lock TA for any crypto operation till next reboot
* --generate-random:

## Raspberry Pi backend (Pi 4 / CM4 / Pi 400 / Pi 5 / CM5 / Pi 500)

Raspberry Pi boards have no OP-TEE. The same `fde-setup` / `fde-reveal-key`
hooks can be built with a backend that uses the VideoCore firmware crypto
service (`rpifwcrypto`). The firmware computes HMAC-SHA256 with the
device-unique OTP private key (key-id 1), so the raw key is never handed to
Linux. The JSON hook protocol is identical; only the sealing backend differs.

Build: `make BACKEND=rpi fde-setup fde-reveal-key fde-key-manager`
(needs `libssl-dev` and `libjson-c-dev`, no OP-TEE, no TA). The binaries
depend only on `libcrypto.so.3` and `libjson-c.so.5`; the Ubuntu Core
initramfs already contains both (pulled in by `cryptsetup`).

### Sealing scheme
* handle (61 bytes): `'P'(1) || nonce(32) || iv(12) || tag(16)`
* `wrap_key = HMAC-SHA256(OTP key, "ubuntu-core-fde:rpi:wrap-key:v1" || nonce)`,
  computed by the firmware
* `sealed_key = AES-256-GCM(wrap_key, iv, aad = 'P' || nonce || iv, key)`
* `lock` sets firmware per-key `READ_LOCKED | HMAC_LOCKED` on the OTP key
  until reboot, so the wrapping keys cannot be derived again after the initrd
  has unlocked the disks. This is the equivalent of `TA_CMD_LOCK`.

### Platform requirements
* **Firmware with rpifwcrypto.** On Pi 4/CM4/Pi 400 it lives in `start4.elf`,
  which the gadget snap ships, so the gadget must carry a recent enough
  firmware. On Pi 5/CM5/Pi 500 it lives in the bootloader EEPROM. Per-key
  locking needs 2026-06 or newer firmware. If the firmware cannot lock,
  `lock` logs a warning and still reports success, and the sealed keys stay
  unsealable by root until reboot. Use `fde-key-manager --otp-key-status` to
  check.
* **Provisioned OTP device key.** On most boards it is blank. `initial-setup`
  fails on a blank key and nothing is provisioned implicitly. Provision once
  (factory step; this permanently programs OTP; the firmware generates an
  ECDSA P-256 key):
  `fde-key-manager --provision-otp-key --i-understand-this-burns-otp`
* **`lock_device_private_key=1` in the gadget's `config.txt`** (strongly
  recommended, required with secure boot). Without it the raw OTP key can be
  read from Linux before `lock` runs; `initial-setup` warns about this.
* `/dev/vcio` must exist in the initrd (raspberrypi firmware + vcio drivers
  built in, or listed as initrd modules). The hook needs the `vcio` interface;
  like `tee` it is `deny-auto-connection`, so it needs a store
  auto-connection grant.
* This is not an HSM. It protects the key from userspace once `lock` and
  `lock_device_private_key=1` are in place, but not from a compromised kernel
  before `lock`, or from physical attacks on the SoC.

### Kernel snap part
```yaml
hooks:
  fde-setup:
    plugs: [vcio]

parts:
  fde-hooks-rpi:
    plugin: nil
    source: https://github.com/canonical/optee-uc-fde.git
    source-type: git
    build-packages:
      - libjson-c-dev:${CRAFT_ARCH_BUILD_FOR}
      - libssl-dev:${CRAFT_ARCH_BUILD_FOR}
      - on amd64 to arm64: [gcc-aarch64-linux-gnu, libc6-dev-arm64-cross]
    build-environment:
      - on arm64:
          - CROSS_COMPILE: ""
      - else:
          - CROSS_COMPILE: "${CRAFT_ARCH_TRIPLET}-"
    override-build: |
      env -u CFLAGS -u CPPFLAGS -u LDFLAGS \
        make -C host/fde_key_manager -R O="${CRAFT_PART_BUILD}/out" \
          BACKEND=rpi -j"${CRAFT_PARALLEL_BUILD_COUNT}" all
      out="${CRAFT_PART_BUILD}/out/fde_key_manager"
      install -Dm0755 "${out}/fde-setup" "${CRAFT_PART_INSTALL}/meta/hooks/fde-setup"
      install -Dm0755 -t "${CRAFT_PART_INSTALL}/usr/bin" \
        "${out}/fde-reveal-key" "${out}/fde-key-manager"
      ln -sf fde-reveal-key "${CRAFT_PART_INSTALL}/usr/bin/fde-setup"
```
`fde-reveal-key` and `fde-setup` must also go into the initrd. With
`ubuntu-core-initramfs`, put them in a feature directory as
`snaps/test-qemu-fde-hooks-kernel` does for the OP-TEE variant (no
`libteec` needed here).

Tests without hardware: `tests/rpi-backend/run.sh <binary dir>` runs the
hooks against a firmware mailbox emulator (`LD_PRELOAD`).

## Acronyms:
* REE: Rich Execution Environment
* TA: Trusted Application
* HUK: Hardware Unique Key

[1]: https://github.com/OP-TEE/optee_os
[2]: https://ubuntu.com/core
