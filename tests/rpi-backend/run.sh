#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# End-to-end test of the Raspberry Pi fde backend (fde-setup, fde-reveal-key,
# fde-key-manager) against the firmware mailbox emulator.
#
# usage: run.sh <dir with BACKEND=rpi binaries>
# needs: cc, libssl-dev, jq, python3-cryptography
set -u
BIN=$(realpath "${1:?usage: $0 <binary dir>}")
HERE=$(dirname "$(realpath "$0")")
M=$(mktemp -d)
trap 'rm -rf "$M"' EXIT
${CC:-cc} -shared -fPIC -O2 -Wall -Wno-deprecated-declarations \
    -o "$M/vcio_mock.so" "$HERE/vcio_mock.c" ${CFLAGS_MOCK:-} -lcrypto -ldl || exit 1
export LD_PRELOAD=$M/vcio_mock.so MOCK_STATE=$M/state
pass=0; fail=0
ok()  { echo "PASS: $*"; pass=$((pass+1)); }
bad() { echo "FAIL: $*"; fail=$((fail+1)); }
reboot() { echo 1 > $MOCK_STATE; }   # status: DEVICE_PRIVATE_KEY, no locks

# fake snapctl for the snap-hook flavour of fde-setup
mkdir -p $M/bin
cat > $M/bin/snapctl <<'S'
#!/bin/sh
case "$1" in
  fde-setup-request) cat "$SNAPCTL_REQ" ;;
  fde-setup-result)  cat > "$SNAPCTL_RES" ;;
esac
S
chmod +x $M/bin/snapctl
export PATH=$M/bin:$PATH SNAPCTL_REQ=$M/req.json SNAPCTL_RES=$M/res.json

reboot
KEY=$(head -c 64 /dev/urandom | base64 -w0)

# 1. features (snap hook flavour)
echo '{"op":"features"}' > $SNAPCTL_REQ; rm -f $SNAPCTL_RES
$BIN/fde-setup 2>/dev/null && [ "$(cat $SNAPCTL_RES)" = '{"features":[]}' ] && ok "features" || bad "features"

# 2. initial-setup (snap hook flavour)
printf '{"op":"initial-setup","key":"%s","key-name":"ubuntu-data"}' "$KEY" > $SNAPCTL_REQ
$BIN/fde-setup 2>$M/setup.log && SEALED=$(jq -r '."sealed-key"' $SNAPCTL_RES) && HANDLE=$(jq -r .handle $SNAPCTL_RES) \
  && [ ${#SEALED} -gt 0 ] && [ "$(echo $HANDLE | base64 -d | wc -c)" = 61 ] && ok "initial-setup (handle 61 bytes)" || { bad "initial-setup"; cat $M/setup.log; }
grep -q "lock_device_private_key=1" $M/setup.log && ok "warns when raw OTP key readable" || bad "missing read-lock warning"

reveal() { printf '{"op":"reveal","sealed-key":"%s","handle":"%s","sealed-key-name":"ubuntu-data"}' "$1" "$2" | $BIN/fde-reveal-key 2>$M/reveal.log; }

# 3. reveal round trip
OUT=$(reveal "$SEALED" "$HANDLE") && [ "$(echo "$OUT" | jq -r .key)" = "$KEY" ] && ok "reveal returns original key" || { bad "reveal"; cat $M/reveal.log; }

# 4. independent check of the documented scheme (python, OTP key known to mock)
python3 - "$SEALED" "$HANDLE" "$KEY" <<'P' && ok "independent decrypt matches documented scheme" || bad "independent decrypt"
import sys, base64, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
otp = bytes([0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00]+list(range(1,17)))
sealed, h, key = (base64.b64decode(x) for x in sys.argv[1:4])
assert h[0] == ord('P') and len(h) == 61
nonce, iv, tag = h[1:33], h[33:45], h[45:61]
wk = hmac.new(otp, b"ubuntu-core-fde:rpi:wrap-key:v1" + nonce, hashlib.sha256).digest()
assert AESGCM(wk).decrypt(iv, sealed + tag, h[:45]) == key
P

# 5. tampering
T_SEALED=$(echo $SEALED | base64 -d | python3 -c "import sys;b=bytearray(sys.stdin.buffer.read());b[0]^=1;sys.stdout.buffer.write(b)" | base64 -w0)
reveal "$T_SEALED" "$HANDLE" >/dev/null && bad "tampered sealed key accepted" || { grep -q "authentication failed" $M/reveal.log && ok "tampered sealed key rejected"; }
T_HANDLE=$(echo $HANDLE | base64 -d | python3 -c "import sys;b=bytearray(sys.stdin.buffer.read());b[5]^=1;sys.stdout.buffer.write(b)" | base64 -w0)
reveal "$SEALED" "$T_HANDLE" >/dev/null && bad "tampered nonce accepted" || ok "tampered nonce rejected"
T_HANDLE=$(echo $HANDLE | base64 -d | python3 -c "import sys;b=bytearray(sys.stdin.buffer.read());b[0]=ord('U');sys.stdout.buffer.write(b)" | base64 -w0)
reveal "$SEALED" "$T_HANDLE" >/dev/null && bad "OP-TEE style handle accepted" || ok "foreign handle version rejected"

# 6. lock, then reveal must fail until reboot
echo '{"op":"lock"}' | $BIN/fde-reveal-key 2>$M/lock.log && ok "lock op succeeds" || bad "lock op"
$BIN/fde-key-manager --ta-lock-status 2>/dev/null | grep -q "LOCKED$" && ok "lock status LOCKED" || bad "lock status"
reveal "$SEALED" "$HANDLE" >/dev/null && bad "reveal after lock succeeded" || { grep -q "locked until next reboot" $M/reveal.log && ok "reveal refused after lock"; }
reboot
OUT=$(reveal "$SEALED" "$HANDLE") && [ "$(echo "$OUT" | jq -r .key)" = "$KEY" ] && ok "reveal works again after reboot" || bad "reveal after reboot"

# 7. old firmware without per-key locking: warn, succeed
MOCK_NO_LOCK=1 sh -c 'echo "{\"op\":\"lock\"}" | '$BIN'/fde-reveal-key' 2>$M/lock.log && grep -q "WARNING: cannot lock" $M/lock.log && ok "lock warns+continues on old firmware" || bad "old firmware lock policy"

# 8. blank OTP key: setup fails, provisioning needs confirmation
printf '{"op":"initial-setup","key":"%s","key-name":"ubuntu-data"}' "$KEY" > $SNAPCTL_REQ; rm -f $SNAPCTL_RES
MOCK_KEY_BLANK=1 $BIN/fde-setup 2>$M/setup.log && bad "setup on blank key succeeded" || { grep -q "not provisioned" $M/setup.log && ok "setup fails on blank OTP key"; }
[ ! -s $SNAPCTL_RES ] && ok "no result emitted on failure" || bad "result emitted on failure"
MOCK_KEY_BLANK=1 $BIN/fde-key-manager --provision-otp-key >/dev/null 2>&1 && bad "provision without confirm" || ok "provision refuses without confirmation"
MOCK_KEY_BLANK=1 $BIN/fde-key-manager --provision-otp-key --i-understand-this-burns-otp >/dev/null 2>&1 && ok "provision with confirmation" || bad "provision with confirmation"
$BIN/fde-key-manager --provision-otp-key --i-understand-this-burns-otp 2>&1 | grep -q "not blank" && ok "provision refuses non-blank slot" || bad "provision on non-blank slot"

# 9. misc CLI
$BIN/fde-key-manager --otp-key-status 2>/dev/null | grep -q "DEVICE_PRIVATE_KEY" && ok "--otp-key-status" || bad "--otp-key-status"
$BIN/fde-key-manager --encrypt-decrypt-selftest >/dev/null 2>&1 && ok "selftest" || bad "selftest"

echo "== $pass passed, $fail failed"; [ $fail = 0 ]
