/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ec_lcl.h"
#include "curve25519_i64.h"

/* Length of Curve 25519 keys */
#define EC_CURVE25519_KEYLEN    32
/* Group degree and order bits */
#define EC_CURVE25519_BITS      253

static void do_curve25519(uint8_t *output, const uint8_t *secret,
                          const uint8_t *bp)
{
    curve25519(output, secret, bp);
}

/* Copy Curve25519 public or private key buffers, allocating is necessary */
static int c25519_init_other(void **dst, const void *src, int secure)
{
    if (*dst == NULL) {
        if (secure)
            *dst = OPENSSL_secure_malloc(EC_CURVE25519_KEYLEN);
        else
            *dst = OPENSSL_malloc(EC_CURVE25519_KEYLEN);
        if (*dst == NULL)
            return 0;
    }
    if (src)
        memcpy(*dst, src, EC_CURVE25519_KEYLEN);
    return 1;
}

static int c25519_group_init(EC_GROUP *grp)
{
    return 1;
}

static int c25519_group_copy(EC_GROUP *dst, const EC_GROUP *src)
{
    return 1;
}

static int c25519_group_get_degree(const EC_GROUP *src)
{
    return EC_CURVE25519_BITS;
}

static int c25519_group_order_bits(const EC_GROUP *src)
{
    return EC_CURVE25519_BITS;
}

static int c25519_set_private(EC_KEY *eckey, const BIGNUM *priv_key)
{
    if (BN_num_bytes(priv_key) > EC_CURVE25519_KEYLEN)
        return 0;
    if (c25519_init_other(&eckey->other, NULL, 1))
        return 0;
    if (BN_bn2lebinpad(priv_key, eckey->other, EC_CURVE25519_KEYLEN)
        != EC_CURVE25519_KEYLEN)
        return 0;
    return 1;
}

static const uint8_t c25519_basepoint[EC_CURVE25519_KEYLEN] = { 9 };

static int c25519_keycheck(const EC_KEY *eckey)
{
    const char *pubkey;
    if (eckey->pub_key == NULL)
        return 0;
    pubkey = eckey->pub_key->other;
    if (pubkey == NULL || pubkey[31] & 0x80)
        return 0;
    if (eckey->priv_key != NULL) {
        uint8_t tmp[EC_CURVE25519_KEYLEN];
        const unsigned char *privkey = eckey->other;
        /* Q: Check private key array too? */
        if (privkey == NULL)
            return 0;
        do_curve25519(tmp, privkey, c25519_basepoint);
        if (CRYPTO_memcmp(pubkey, tmp, EC_CURVE25519_KEYLEN) == 0)
            return 1;
        return 0;
    } else {
        return 1;
    }
}

static int c25519_keygenpub(EC_KEY *eckey)
{
    do_curve25519(eckey->pub_key->other, eckey->other, c25519_basepoint);
    return 1;
}

static int c25519_keygen(EC_KEY *eckey)
{
    unsigned char *key;
    if (c25519_init_other(&eckey->other, NULL, 1) == 0)
        return 0;
    key = eckey->other;
    if (RAND_bytes(key, EC_CURVE25519_KEYLEN) <= 0)
        return 0;
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    if (eckey->priv_key == NULL)
        eckey->priv_key = BN_secure_new();
    if (eckey->priv_key == NULL)
        return 0;
    if (BN_lebin2bn(eckey->other, EC_CURVE25519_KEYLEN, eckey->priv_key) ==
        NULL)
        return 0;
    if (eckey->pub_key == NULL)
        eckey->pub_key = EC_POINT_new(eckey->group);
    if (eckey->pub_key == NULL)
        return 0;
    return c25519_keygenpub(eckey);
}

static void c25519_keyfinish(EC_KEY *eckey)
{
    OPENSSL_secure_free(eckey->other);
    eckey->other = NULL;
}

static int c25519_keycopy(EC_KEY *dest, const EC_KEY *src)
{
    if (src->other == NULL)
        return 0;
    return c25519_init_other(&dest->other, src->other, 1);
}

static int c25519_oct2priv(EC_KEY *eckey, unsigned char *buf, size_t len)
{
    if (len != EC_CURVE25519_KEYLEN)
        return 0;
    if (c25519_init_other(&eckey->other, buf, 1) == 0)
        return 0;
    if (eckey->priv_key == NULL)
        eckey->priv_key = BN_secure_new();
    if (eckey->priv_key == NULL)
        return 0;
    if (BN_lebin2bn(buf, EC_CURVE25519_KEYLEN, eckey->priv_key) == NULL)
        return 0;
    return 1;
}

static size_t c25519_priv2oct(const EC_KEY *eckey,
                              unsigned char *buf, size_t len)
{
    size_t keylen = EC_CURVE25519_KEYLEN;
    if (eckey->other == NULL)
        return 0;
    if (buf != NULL) {
        if (len < keylen)
            return 0;
        memcpy(buf, eckey->other, keylen);
    }
    return keylen;
}

static int c25519_point_init(EC_POINT *pt)
{
    return c25519_init_other(&pt->other, NULL, 0);
}

static void c25519_point_finish(EC_POINT *pt)
{
    OPENSSL_free(pt->other);
    pt->other = NULL;
}

static void c25519_point_clear_finish(EC_POINT *pt)
{
    OPENSSL_clear_free(pt->other, EC_CURVE25519_KEYLEN);
    pt->other = NULL;
}

static int c25519_point_copy(EC_POINT *dst, const EC_POINT *src)
{
    memcpy(dst->other, src->other, EC_CURVE25519_KEYLEN);
    return 1;
}

static size_t c25519_point2oct(const EC_GROUP *grp, const EC_POINT *pt,
                               point_conversion_form_t form,
                               unsigned char *buf, size_t len, BN_CTX *ctx)
{
    if (buf != NULL) {
        if (len < EC_CURVE25519_KEYLEN)
            return 0;
        memcpy(buf, pt->other, EC_CURVE25519_KEYLEN);
    }
    return EC_CURVE25519_KEYLEN;
}

static int c25519_oct2point(const EC_GROUP *grp, EC_POINT *pt,
                            const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    if (len != EC_CURVE25519_KEYLEN)
        return 0;
    /* Check public key validity */
    if (buf[31] & 0x80)
        return 0;
    memcpy(pt->other, buf, EC_CURVE25519_KEYLEN);
    return 1;
}

static int c25519_compute_key(void *out, size_t outlen,
                              const EC_POINT *pub_key, const EC_KEY *ecdh,
                              void *(*KDF) (const void *in, size_t inlen,
                                            void *out, size_t *outlen))
{
    unsigned char *key;
    int ret = -1;
    if (ecdh->other == NULL)
        return -1;
    key = OPENSSL_malloc(EC_CURVE25519_KEYLEN);
    if (key == NULL)
        return -1;
    do_curve25519(key, ecdh->other, pub_key->other);
    if (KDF) {
        if (KDF(key, EC_CURVE25519_KEYLEN, out, &outlen) == NULL)
            goto err;
        ret = outlen;
    } else {
        if (outlen > EC_CURVE25519_KEYLEN)
            outlen = EC_CURVE25519_KEYLEN;
        memcpy(out, key, outlen);
        ret = outlen;
    }

 err:
    OPENSSL_clear_free(key, EC_CURVE25519_KEYLEN);
    return ret;
}

const EC_METHOD *ec_curve25519_meth(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_CUSTOM_CURVE,
        NID_undef,
        c25519_group_init,      /* group_init */
        0,                      /* group_finish */
        0,                      /* group_clear_finish */
        c25519_group_copy,      /* group_copy */
        0,                      /* group_set_curve */
        0,                      /* group_get_curve */
        c25519_group_get_degree,
        c25519_group_order_bits,
        0,                      /* group_check_discriminant */
        c25519_point_init,
        c25519_point_finish,
        c25519_point_clear_finish,
        c25519_point_copy,
        0,                      /* point_set_to_infinity */
        0,                      /* set_Jprojective_coordinates_GFp */
        0,                      /* get_Jprojective_coordinates_GFp */
        0,                      /* point_set_affine_coordinates */
        0,                      /* point_get_affine_coordinates */
        0,                      /* point_set_compressed_coordinates */
        c25519_point2oct,
        c25519_oct2point,
        0,                      /* simple_add */
        0,                      /* simple_dbl */
        0,                      /* simple_invert */
        0,                      /* simple_is_at_infinity */
        0,                      /* simple_is_on_curve */
        0,                      /* simple_cmp */
        0,                      /* simple_make_affine */
        0,                      /* simple_points_make_affine */
        0,                      /* points_mul */
        0,                      /* precompute_mult */
        0,                      /* have_precompute_mult */
        0,                      /* field_mul */
        0,                      /* field_sqr */
        0,                      /* field_div */
        0,                      /* field_encode */
        0,                      /* field_decode */
        0,                      /* field_set_to_one */
        c25519_priv2oct,
        c25519_oct2priv,
        c25519_set_private,
        c25519_keygen,
        c25519_keycheck,
        c25519_keygenpub,
        c25519_keycopy,
        c25519_keyfinish,
        c25519_compute_key
    };

    return &ret;
}
