/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 */

/*
 * TA v2: keys sealed to a measured boot, and retired by a counter in RPMB.
 *
 * The measurement register is extend-only and lives as long as the TA
 * instance, which is single instance, kept alive, and kept crashed: a TA that
 * panics is not created again with an empty register before the reboot.
 * U-Boot extends it first, with the FIT it boots and the final bootargs; the
 * initrd then extends it with the system slot it maps. Each extend is
 *
 *     register = SHA-256(register || SHA-256(event))
 *
 * from 32 zero bytes, as a PCR.
 *
 * A v2 key handle carries the register values the key may be unsealed for,
 * and the counter value it was sealed at, both authenticated as AES-GCM
 * additional data. The key unseals only while the register is one of those
 * values, and, when the device has RPMB, while the counter in RPMB is not
 * above the handle's. Raising the counter retires every key sealed at a
 * lower value. A device that sealed a v2 key with RPMB is "armed": it refuses
 * v1 handles and v2 handles sealed without the counter from then on.
 *
 * Without RPMB secure storage (CFG_RPMB_FS=n, or no RPMB key programmed on an
 * open board) keys are sealed and unsealed without the counter, the register
 * still enforced, unless the TA is built with CFG_FDE_V2_REQUIRE_RPMB=y, see
 * counter_state.
 */

#include <pta_system.h>
#include <stddef.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_handler_ta_handle.h"

#define V2_IV_SIZE      16
#define V2_NONCE_SIZE   32
#define V2_TAG_SIZE     16
#define V2_HANDLE_VERSION 'V'
#define V2_FLAG_COUNTER 0x01

/*
 * The header of a v2 key handle, followed by n_values register values of
 * REGISTER_SIZE bytes each. Every field but the tag is additional data of the
 * AES-GCM encryption of the key.
 */
struct key_handle_v2 {
    uint8_t version;
    uint8_t flags;
    uint8_t n_values;
    uint8_t reserved;
    uint8_t counter[8]; /* little endian */
    uint8_t iv[V2_IV_SIZE];
    uint8_t nonce[V2_NONCE_SIZE];
    uint8_t tag[V2_TAG_SIZE];
} __attribute__((packed));

#define V2_HANDLE_SIZE(n) (sizeof(struct key_handle_v2) + (size_t)(n) * REGISTER_SIZE)

/* the counter object in RPMB */
#define COUNTER_OBJECT_ID   "uc-fde-v2-counter"
#define COUNTER_MAGIC       0x55434644 /* "UCFD" */
struct counter_object {
    uint32_t magic;
    uint32_t armed;
    uint64_t counter;
};

static uint8_t _register[REGISTER_SIZE];
static uint32_t _extends;

/*
 * The values the register had after each of the first REGISTER_HISTORY
 * extends of the boot. A reseal is authorized by any of them: the boot was one
 * the key unseals for when it had that value, as the keys of ubuntu-data are
 * after snap-bootstrap extends the register with the claim of the apps slots.
 * An unseal takes the register as it is.
 */
#define REGISTER_HISTORY 8
static uint8_t _history[REGISTER_HISTORY][REGISTER_SIZE];

static TEE_Result sha256(const void *a, size_t a_len, const void *b,
                         size_t b_len, uint8_t out[REGISTER_SIZE]) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_GENERIC;
    size_t out_len = REGISTER_SIZE;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res)
        return res;
    if (a_len)
        TEE_DigestUpdate(op, a, a_len);
    res = TEE_DigestDoFinal(op, b, b_len, out, &out_len);
    TEE_FreeOperation(op);
    if (!res && out_len != REGISTER_SIZE)
        res = TEE_ERROR_SECURITY;
    return res;
}

TEE_Result cmd_extend(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    uint8_t digest[REGISTER_SIZE] = { };
    TEE_Result res = TEE_ERROR_GENERIC;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    if ((!params[0].memref.buffer && params[0].memref.size) ||
        params[0].memref.size > MAX_EVENT_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;

    res = sha256(NULL, 0, params[0].memref.buffer, params[0].memref.size, digest);
    if (res)
        return res;
    res = sha256(_register, sizeof(_register), digest, sizeof(digest), _register);
    if (res) {
        /* a register that may be half written measures nothing any more */
        TEE_Panic(res);
    }
    if (_extends < REGISTER_HISTORY)
        memcpy(_history[_extends], _register, REGISTER_SIZE);
    _extends++;
    DMSG("fde_key_handler: register extended, %"PRIu32" events", _extends);
    return TEE_SUCCESS;
}

TEE_Result cmd_get_register(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                 TEE_PARAM_TYPE_VALUE_OUTPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[0].memref.size < REGISTER_SIZE) {
        params[0].memref.size = REGISTER_SIZE;
        return TEE_ERROR_SHORT_BUFFER;
    }
    memcpy(params[0].memref.buffer, _register, REGISTER_SIZE);
    params[0].memref.size = REGISTER_SIZE;
    params[1].value.a = _extends;
    params[1].value.b = 0;
    return TEE_SUCCESS;
}

/*
 * The counter object lives in RPMB, whose frames the normal world carries.
 * Their data and the write counter are authenticated, but OP-TEE takes the
 * result code of a frame before it checks its MAC, so the normal world can
 * make any RPMB access fail, with any error, "item not found" included. The
 * counter is therefore never written from what a failed read implies:
 *  - an object that is not found is created without overwrite, so an object
 *    that is there after all makes the create fail, and that is tampering;
 *  - an update opens the object it changes, reads it again, and writes it
 *    only when it holds what the caller read;
 *  - a counter that was there this boot cannot go away before the reboot.
 *
 * With FDE_V2_REQUIRE_RPMB, a production build for a device whose RPMB key
 * is provisioned, RPMB that cannot be used fails every call that needs the
 * counter, a v1 unseal included, and v2 keys sealed without the counter are
 * refused. v1 keys still unseal until the first v2 seal arms the device, so a
 * v1 install can move its keys to v2. Without it, a device with no usable
 * RPMB from the start of the boot seals and unseals without the counter,
 * which a normal world that blocks RPMB from the start of the boot gets as
 * well: the downgrade a development build accepts.
 */
#ifndef FDE_V2_REQUIRE_RPMB
#define FDE_V2_REQUIRE_RPMB 0
#endif

/* the counter was read or written this boot */
static bool _rpmb_seen;
/* RPMB answered in a way only tampering gives: refuse until the reboot */
static bool _rpmb_tampered;

static TEE_Result tampered(const char *what) {
    EMSG("fde_key_handler: RPMB tampered with: %s, refusing until reboot", what);
    _rpmb_tampered = true;
    return TEE_ERROR_SECURITY;
}

static TEE_Result check_counter(const struct counter_object *obj, size_t read) {
    if (read != sizeof(*obj) || obj->magic != COUNTER_MAGIC || obj->armed > 1)
        return tampered("the counter object is malformed");
    return TEE_SUCCESS;
}

/*
 * no_rpmb is the counter state of a device without usable RPMB: none, when
 * that is allowed, else an error.
 */
static TEE_Result no_rpmb(TEE_Result res, bool *rpmb) {
    if (FDE_V2_REQUIRE_RPMB || _rpmb_seen) {
        EMSG("fde_key_handler: the counter in RPMB is not available: %#"PRIx32, res);
        return TEE_ERROR_STORAGE_NOT_AVAILABLE;
    }
    *rpmb = false;
    return TEE_SUCCESS;
}

/*
 * counter_state returns the counter, whether the device is armed, and whether
 * it has the counter at all. The first call that finds RPMB without the
 * counter object creates it, zero and unarmed.
 *
 * Storage errors libutee does not pass on, TEE_ERROR_SECURITY for a MAC that
 * does not match among them, panic the TA, which stays crashed until the
 * reboot: they fail closed as well.
 */
static TEE_Result counter_state(struct counter_object *obj, bool *rpmb) {
    TEE_ObjectHandle h = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_GENERIC;
    size_t read = 0;

    *rpmb = false;
    memset(obj, 0, sizeof(*obj));
    obj->magic = COUNTER_MAGIC;
    if (_rpmb_tampered)
        return TEE_ERROR_SECURITY;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_RPMB, COUNTER_OBJECT_ID,
                                   strlen(COUNTER_OBJECT_ID),
                                   TEE_DATA_FLAG_ACCESS_READ, &h);
    if (res == TEE_SUCCESS) {
        res = TEE_ReadObjectData(h, obj, sizeof(*obj), &read);
        TEE_CloseObject(h);
        if (res)
            return no_rpmb(res, rpmb);
        res = check_counter(obj, read);
        if (res)
            return res;
        _rpmb_seen = true;
        *rpmb = true;
        return TEE_SUCCESS;
    }
    if (res == TEE_ERROR_CORRUPT_OBJECT) {
        /* OP-TEE removes a corrupt object, the counter with it */
        return tampered("the counter object is corrupt");
    }
    if (res != TEE_ERROR_ITEM_NOT_FOUND)
        return no_rpmb(res, rpmb);
    if (_rpmb_seen) {
        /* it was there this boot, and nothing in this TA removes it */
        return tampered("the counter object went away");
    }

    /* not there, or RPMB not usable, or the normal world says so */
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_RPMB, COUNTER_OBJECT_ID,
                                     strlen(COUNTER_OBJECT_ID),
                                     TEE_DATA_FLAG_ACCESS_READ |
                                     TEE_DATA_FLAG_ACCESS_WRITE,
                                     TEE_HANDLE_NULL, obj, sizeof(*obj), &h);
    if (res == TEE_ERROR_ACCESS_CONFLICT)
        return tampered("the counter object was there after all");
    if (res)
        return no_rpmb(res, rpmb);
    TEE_CloseObject(h);
    DMSG("fde_key_handler: created the counter in RPMB");
    _rpmb_seen = true;
    *rpmb = true;
    return TEE_SUCCESS;
}

/*
 * update_counter writes the counter, and the armed flag, over the counter
 * object as seen holds it. Neither goes back. The object is opened, read and
 * compared to seen again, so a write never rests on a read that failed.
 */
static TEE_Result update_counter(const struct counter_object *seen,
                                 uint64_t counter, bool arm) {
    struct counter_object cur = { };
    struct counter_object next = *seen;
    TEE_ObjectHandle h = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_GENERIC;
    size_t read = 0;

    if (_rpmb_tampered)
        return TEE_ERROR_SECURITY;
    if (counter < seen->counter)
        return TEE_ERROR_BAD_PARAMETERS;
    next.counter = counter;
    if (arm)
        next.armed = 1;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_RPMB, COUNTER_OBJECT_ID,
                                   strlen(COUNTER_OBJECT_ID),
                                   TEE_DATA_FLAG_ACCESS_READ |
                                   TEE_DATA_FLAG_ACCESS_WRITE, &h);
    if (res == TEE_ERROR_ITEM_NOT_FOUND || res == TEE_ERROR_CORRUPT_OBJECT)
        return tampered("the counter object went away");
    if (res)
        return TEE_ERROR_STORAGE_NOT_AVAILABLE;
    res = TEE_ReadObjectData(h, &cur, sizeof(cur), &read);
    if (res) {
        res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
        goto out;
    }
    res = check_counter(&cur, read);
    if (res)
        goto out;
    /* commands of a single instance TA do not interleave */
    if (cur.counter != seen->counter || cur.armed != seen->armed) {
        res = tampered("the counter changed under the TA");
        goto out;
    }
    res = TEE_SeekObjectData(h, 0, TEE_DATA_SEEK_SET);
    if (!res)
        res = TEE_WriteObjectData(h, &next, sizeof(next));
    if (res)
        res = TEE_ERROR_STORAGE_NOT_AVAILABLE;
out:
    TEE_CloseObject(h);
    return res;
}

/*
 * v1_handles_refused returns true once a v2 key was sealed with RPMB, and
 * whenever the counter cannot be told, which includes a build that requires
 * RPMB finding none.
 */
bool v1_handles_refused(void) {
    struct counter_object obj;
    bool rpmb = false;

    if (counter_state(&obj, &rpmb) != TEE_SUCCESS)
        return true;
    return rpmb && obj.armed;
}

TEE_Result cmd_get_counter(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    struct counter_object obj;
    TEE_Result res = TEE_ERROR_GENERIC;
    bool rpmb = false;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                 TEE_PARAM_TYPE_VALUE_OUTPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    res = counter_state(&obj, &rpmb);
    if (res)
        return res;
    params[0].value.a = (uint32_t)obj.counter;
    params[0].value.b = (uint32_t)(obj.counter >> 32);
    params[1].value.a = rpmb ? 1 : 0;
    params[1].value.b = obj.armed ? 1 : 0;
    return TEE_SUCCESS;
}

TEE_Result cmd_raise_counter(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    struct counter_object obj;
    TEE_Result res = TEE_ERROR_GENERIC;
    bool rpmb = false;
    uint64_t value = 0;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    value = ((uint64_t)params[0].value.b << 32) | params[0].value.a;
    res = counter_state(&obj, &rpmb);
    if (res)
        return res;
    if (!rpmb)
        return TEE_ERROR_STORAGE_NOT_AVAILABLE;
    if (value < obj.counter) {
        EMSG("fde_key_handler: the counter does not go back");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (value == obj.counter)
        return TEE_SUCCESS;
    return update_counter(&obj, value, false);
}

static void put_le64(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_le64(const uint8_t in[8]) {
    uint64_t v = 0;

    for (int i = 0; i < 8; i++)
        v |= (uint64_t)in[i] << (8 * i);
    return v;
}

/*
 * v2_crypto encrypts or decrypts a key under the key derived for the handle's
 * nonce, with everything of the handle but its tag as additional data.
 */
static TEE_Result v2_crypto(TEE_OperationMode mode, struct key_handle_v2 *handle,
                            uint8_t *in, size_t in_size,
                            uint8_t *out, size_t *out_size) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
    uint8_t derived[TA_DERIVED_KEY_MAX_SIZE] = { };
    TEE_Attribute attr = { };
    TEE_Result res = TEE_ERROR_GENERIC;
    uint8_t tag[V2_TAG_SIZE] = { };
    size_t tag_len = V2_TAG_SIZE;
    size_t aad_head = offsetof(struct key_handle_v2, tag);

    res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, mode, sizeof(derived) * 8);
    if (res)
        return res;
    res = derive_ta_unique_key(derived, sizeof(derived), handle->nonce,
                               sizeof(handle->nonce));
    if (res)
        goto out_op;
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(derived) * 8, &hkey);
    if (res)
        goto out_op;
    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = derived;
    attr.content.ref.length = sizeof(derived);
    res = TEE_PopulateTransientObject(hkey, &attr, 1);
    if (res)
        goto out_key;
    res = TEE_SetOperationKey(op, hkey);
    if (res)
        goto out_key;
    res = TEE_AEInit(op, handle->iv, V2_IV_SIZE, V2_TAG_SIZE * 8, 0, 0);
    if (res)
        goto out_key;
    TEE_AEUpdateAAD(op, handle, aad_head);
    TEE_AEUpdateAAD(op, (uint8_t *)handle + sizeof(*handle),
                    (size_t)handle->n_values * REGISTER_SIZE);
    if (mode == TEE_MODE_ENCRYPT) {
        res = TEE_AEEncryptFinal(op, in, in_size, out, out_size, handle->tag, &tag_len);
        if (!res && (tag_len != V2_TAG_SIZE || *out_size != in_size))
            res = TEE_ERROR_SECURITY;
    } else {
        memcpy(tag, handle->tag, V2_TAG_SIZE);
        res = TEE_AEDecryptFinal(op, in, in_size, out, out_size, tag, V2_TAG_SIZE);
        if (!res && *out_size != in_size)
            res = TEE_ERROR_SECURITY;
    }

out_key:
    TEE_FreeTransientObject(hkey);
out_op:
    TEE_FreeOperation(op);
    memzero_explicit(derived, sizeof(derived));
    return res;
}

/*
 * cmd_key_encrypt_v2 seals a key.
 *   params[0] memref input:  the key
 *   params[1] memref input:  the policy: the counter, 8 bytes little endian,
 *                            then 1 to MAX_REGISTER_VALUES register values
 *   params[2] memref output: the handle, V2_HANDLE_SIZE(values)
 *   params[3] memref output: the sealed key, the size of the key
 * A counter below the one in RPMB is refused: such a key would never unseal.
 */
TEE_Result cmd_key_encrypt_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    struct counter_object obj;
    struct key_handle_v2 *handle = NULL;
    uint8_t *policy = NULL;
    size_t policy_size = 0, n = 0, handle_size = 0;
    size_t out_size = 0;
    uint8_t rng[V2_IV_SIZE + V2_NONCE_SIZE] = { };
    uint64_t counter = 0;
    bool rpmb = false;
    TEE_Result res = TEE_ERROR_GENERIC;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT))
        return TEE_ERROR_BAD_PARAMETERS;
    if (!params[0].memref.buffer || !params[0].memref.size ||
        params[0].memref.size > MAX_BUF_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    policy = params[1].memref.buffer;
    policy_size = params[1].memref.size;
    if (!policy || policy_size < 8 + REGISTER_SIZE ||
        (policy_size - 8) % REGISTER_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    n = (policy_size - 8) / REGISTER_SIZE;
    if (n > MAX_REGISTER_VALUES)
        return TEE_ERROR_BAD_PARAMETERS;
    handle_size = V2_HANDLE_SIZE(n);
    if (params[2].memref.size < handle_size || params[3].memref.size < params[0].memref.size) {
        params[2].memref.size = handle_size;
        params[3].memref.size = params[0].memref.size;
        return TEE_ERROR_SHORT_BUFFER;
    }
    counter = get_le64(policy);

    res = counter_state(&obj, &rpmb);
    if (res)
        return res;
    if (rpmb && counter < obj.counter) {
        EMSG("fde_key_handler: refusing to seal below the counter");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = TEE_Malloc(handle_size, TEE_MALLOC_FILL_ZERO);
    if (!handle)
        return TEE_ERROR_OUT_OF_MEMORY;
    handle->version = V2_HANDLE_VERSION;
    handle->flags = rpmb ? V2_FLAG_COUNTER : 0;
    handle->n_values = (uint8_t)n;
    put_le64(handle->counter, rpmb ? counter : 0);
    TEE_GenerateRandom(rng, sizeof(rng));
    memcpy(handle->iv, rng, V2_IV_SIZE);
    memcpy(handle->nonce, rng + V2_IV_SIZE, V2_NONCE_SIZE);
    memzero_explicit(rng, sizeof(rng));
    memcpy((uint8_t *)handle + sizeof(*handle), policy + 8, n * REGISTER_SIZE);

    out_size = params[0].memref.size;
    res = v2_crypto(TEE_MODE_ENCRYPT, handle, params[0].memref.buffer,
                    params[0].memref.size, params[3].memref.buffer, &out_size);
    if (res)
        goto out;

    if (rpmb && !obj.armed) {
        /* from now on, keys sealed without the counter go */
        res = update_counter(&obj, obj.counter, true);
        if (res)
            goto out;
    }
    memcpy(params[2].memref.buffer, handle, handle_size);
    params[2].memref.size = handle_size;
    params[3].memref.size = out_size;
out:
    TEE_Free(handle);
    return res;
}

/* matches returns true if the register value is one of the handle's values */
static bool matches(const struct key_handle_v2 *handle, const uint8_t *value) {
    const uint8_t *values = (const uint8_t *)handle + sizeof(*handle);
    bool match = false;

    for (size_t i = 0; i < handle->n_values; i++) {
        if (!consttime_memcmp(values + i * REGISTER_SIZE, value, REGISTER_SIZE))
            match = true;
    }
    return match;
}

/*
 * open_v2 checks a v2 handle and opens its sealed key into key, out_size
 * bytes, when the running boot may: the handle is the one sealed, its counter
 * is not retired, and the register is one of its values, or, for a reseal,
 * had one of them earlier in the boot. handle is a copy the normal world
 * cannot change.
 */
static TEE_Result open_v2(struct key_handle_v2 *handle, size_t handle_size,
                          uint8_t *sealed, size_t sealed_size,
                          uint8_t *key, size_t *out_size, bool reseal) {
    struct counter_object obj;
    bool rpmb = false, match = false;
    TEE_Result res = TEE_ERROR_GENERIC;

    if (handle->version != V2_HANDLE_VERSION || handle->n_values == 0 ||
        handle->n_values > MAX_REGISTER_VALUES ||
        handle_size != V2_HANDLE_SIZE(handle->n_values))
        return TEE_ERROR_BAD_PARAMETERS;

    res = counter_state(&obj, &rpmb);
    if (res)
        return res;
    if (handle->flags & V2_FLAG_COUNTER) {
        if (!rpmb) {
            EMSG("fde_key_handler: the key needs the counter, and RPMB is not there");
            return TEE_ERROR_ACCESS_DENIED;
        }
        if (get_le64(handle->counter) < obj.counter) {
            EMSG("fde_key_handler: the key was retired by the counter");
            return TEE_ERROR_ACCESS_DENIED;
        }
    } else if (FDE_V2_REQUIRE_RPMB || (rpmb && obj.armed)) {
        EMSG("fde_key_handler: the key was sealed without the counter");
        return TEE_ERROR_ACCESS_DENIED;
    }

    *out_size = sealed_size;
    /* the policy is checked only once the tag says it is the sealed one */
    res = v2_crypto(TEE_MODE_DECRYPT, handle, sealed, sealed_size, key, out_size);
    if (res)
        return res;

    match = matches(handle, _register);
    for (uint32_t i = 0; reseal && i < _extends && i < REGISTER_HISTORY; i++) {
        if (matches(handle, _history[i]))
            match = true;
    }
    if (!match) {
        EMSG("fde_key_handler: the boot measured is not one the key is sealed to");
        memzero_explicit(key, sealed_size);
        return TEE_ERROR_ACCESS_DENIED;
    }
    return TEE_SUCCESS;
}

/* copy_handle copies a v2 handle the normal world shares */
static struct key_handle_v2 *copy_handle(const TEE_Param *param) {
    struct key_handle_v2 *handle = NULL;

    if (!param->memref.buffer || param->memref.size < sizeof(*handle) ||
        param->memref.size > V2_HANDLE_SIZE(MAX_REGISTER_VALUES))
        return NULL;
    handle = TEE_Malloc(param->memref.size, TEE_MALLOC_FILL_ZERO);
    if (handle)
        memcpy(handle, param->memref.buffer, param->memref.size);
    return handle;
}

/*
 * cmd_key_decrypt_v2 unseals a key.
 *   params[0] memref input:  the sealed key
 *   params[1] memref input:  the handle
 *   params[2] memref output: the key
 */
TEE_Result cmd_key_decrypt_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    struct key_handle_v2 *handle = NULL;
    size_t out_size = 0, sealed_size = 0;
    TEE_Result res = TEE_ERROR_GENERIC;
    uint8_t *key = NULL;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                 TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    sealed_size = params[0].memref.size;
    if (!params[0].memref.buffer || !sealed_size || sealed_size > MAX_BUF_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    if (params[2].memref.size < sealed_size) {
        params[2].memref.size = sealed_size;
        return TEE_ERROR_SHORT_BUFFER;
    }
    handle = copy_handle(&params[1]);
    if (!handle)
        return TEE_ERROR_BAD_PARAMETERS;
    key = TEE_Malloc(sealed_size, TEE_MALLOC_FILL_ZERO);
    if (!key) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    res = open_v2(handle, params[1].memref.size, params[0].memref.buffer,
                  sealed_size, key, &out_size, false);
    if (res)
        goto out;
    memcpy(params[2].memref.buffer, key, out_size);
    params[2].memref.size = out_size;
out:
    if (key) {
        memzero_explicit(key, sealed_size);
        TEE_Free(key);
    }
    TEE_Free(handle);
    return res;
}

/*
 * cmd_key_reseal_v2 seals a key again, to new register values or a new
 * counter, without revealing it: the running boot has to be one the old handle
 * unseals for, now or earlier in the boot, so this works once the TA is locked,
 * as a reseal of a refresh needs, and after the register was extended past the
 * value the key unsealed at. The new counter is not below the one in RPMB.
 *   params[0] memref input:  the sealed key
 *   params[1] memref input:  the handle
 *   params[2] memref input:  the new policy, as for TA_CMD_KEY_ENCRYPT_V2
 *   params[3] memref output: the new handle, then the newly sealed key
 */
TEE_Result cmd_key_reseal_v2(uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    struct counter_object obj;
    struct key_handle_v2 *handle = NULL, *fresh = NULL;
    size_t sealed_size = 0, out_size = 0, n = 0, fresh_size = 0;
    uint8_t *policy = NULL, *key = NULL, *out = NULL;
    uint8_t rng[V2_IV_SIZE + V2_NONCE_SIZE] = { };
    size_t policy_size = 0;
    uint64_t counter = 0;
    bool rpmb = false;
    TEE_Result res = TEE_ERROR_GENERIC;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT))
        return TEE_ERROR_BAD_PARAMETERS;
    sealed_size = params[0].memref.size;
    if (!params[0].memref.buffer || !sealed_size || sealed_size > MAX_BUF_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    policy = params[2].memref.buffer;
    policy_size = params[2].memref.size;
    if (!policy || policy_size < 8 + REGISTER_SIZE ||
        (policy_size - 8) % REGISTER_SIZE)
        return TEE_ERROR_BAD_PARAMETERS;
    n = (policy_size - 8) / REGISTER_SIZE;
    if (n > MAX_REGISTER_VALUES)
        return TEE_ERROR_BAD_PARAMETERS;
    fresh_size = V2_HANDLE_SIZE(n);
    if (params[3].memref.size < fresh_size + sealed_size) {
        params[3].memref.size = fresh_size + sealed_size;
        return TEE_ERROR_SHORT_BUFFER;
    }
    counter = get_le64(policy);

    handle = copy_handle(&params[1]);
    if (!handle)
        return TEE_ERROR_BAD_PARAMETERS;
    key = TEE_Malloc(sealed_size, TEE_MALLOC_FILL_ZERO);
    out = TEE_Malloc(sealed_size, TEE_MALLOC_FILL_ZERO);
    fresh = TEE_Malloc(fresh_size, TEE_MALLOC_FILL_ZERO);
    if (!key || !out || !fresh) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    res = open_v2(handle, params[1].memref.size, params[0].memref.buffer,
                  sealed_size, key, &out_size, true);
    if (res)
        goto out;

    res = counter_state(&obj, &rpmb);
    if (res)
        goto out;
    if (rpmb && counter < obj.counter) {
        EMSG("fde_key_handler: refusing to seal below the counter");
        res = TEE_ERROR_BAD_PARAMETERS;
        goto out;
    }
    fresh->version = V2_HANDLE_VERSION;
    fresh->flags = rpmb ? V2_FLAG_COUNTER : 0;
    fresh->n_values = (uint8_t)n;
    put_le64(fresh->counter, rpmb ? counter : 0);
    TEE_GenerateRandom(rng, sizeof(rng));
    memcpy(fresh->iv, rng, V2_IV_SIZE);
    memcpy(fresh->nonce, rng + V2_IV_SIZE, V2_NONCE_SIZE);
    memzero_explicit(rng, sizeof(rng));
    memcpy((uint8_t *)fresh + sizeof(*fresh), policy + 8, n * REGISTER_SIZE);

    res = v2_crypto(TEE_MODE_ENCRYPT, fresh, key, out_size, out, &out_size);
    if (res)
        goto out;
    if (rpmb && !obj.armed) {
        res = update_counter(&obj, obj.counter, true);
        if (res)
            goto out;
    }
    memcpy(params[3].memref.buffer, fresh, fresh_size);
    memcpy((uint8_t *)params[3].memref.buffer + fresh_size, out, out_size);
    params[3].memref.size = fresh_size + out_size;
out:
    if (key) {
        memzero_explicit(key, sealed_size);
        TEE_Free(key);
    }
    TEE_Free(out);
    TEE_Free(fresh);
    TEE_Free(handle);
    return res;
}
