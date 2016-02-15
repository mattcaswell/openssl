/*
 * Written by Matt Caswell for the OpenSSL project.
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
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <internal/constant_time_locl.h>
#include <internal/bn_25519.h>
#include "ec_lcl.h"

static inline void cswap(unsigned int swap, BIGNUM **a, BIGNUM **b)
{
    unsigned char *atmp, *btmp;
    BIGNUM *abntmp, *bbntmp;
    unsigned int mask;
    unsigned int i;

    abntmp = *a;
    bbntmp = *b;
    atmp = (unsigned char *)&abntmp;
    btmp = (unsigned char *)&bbntmp;
    mask = -swap;
    for (i = 0; i < sizeof(BIGNUM *); i++) {
        ((unsigned char *)a)[i] = constant_time_select_8(mask, btmp[i],
                                                         atmp[i]);
        ((unsigned char *)b)[i] = constant_time_select_8(mask, atmp[i],
                                                         btmp[i]);
    }
}

#define NUM_CHARS_25519     32
#define NUM_BITS_25519      255

int curve25519_impl(uint8_t *output, const uint8_t *secret,
                            const uint8_t *bp)
{
    int ret = 0;
    unsigned char u[NUM_CHARS_25519];
    unsigned char k[NUM_CHARS_25519];
    unsigned char outtmp[NUM_CHARS_25519];
    /* Variable naming as per RFC7748 for ease of cross-reference */
    BIGNUM *x_1 = NULL, *x_2 = NULL, *z_2 = NULL, *x_3 = NULL, *z_3 = NULL;
    BIGNUM *A = NULL, *AA = NULL, *B = NULL, *BB = NULL, *E = NULL;
    BIGNUM *C = NULL, *D = NULL, *DA = NULL, *CB = NULL;
    const BIGNUM *p25519 = NULL, *pminus2 = NULL, *a24 = NULL;
    BN_CTX *ctx;
    int t;
    int kptr = NUM_CHARS_25519 - 1;
    unsigned int swap = 0;
    unsigned int k_t;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);

    /* p25519 = 2^255 - 19 */
    p25519 = &_bignum_curve25519_p;

    /* pminus2 = p25519 - 2 */
    pminus2 = &_bignum_curve25519_pminus2;

    /* a24 = 121665 */
    a24 = &_bignum_curve25519_a24;

    /* Put into big endian order */
    BUF_reverse(u, bp, NUM_CHARS_25519);
    memcpy(k, secret, NUM_CHARS_25519);

    /* Ignore the msb of the most significant byte for u */
    u[0] &= 127;

    k[0] &= 248;
    k[NUM_CHARS_25519 - 1] &= 127;
    k[NUM_CHARS_25519 - 1] |= 64;

    x_1 = BN_CTX_get(ctx);
    x_2 = BN_CTX_get(ctx);
    z_2 = BN_CTX_get(ctx);
    x_3 = BN_CTX_get(ctx);
    z_3 = BN_CTX_get(ctx);
    A = BN_CTX_get(ctx);
    AA = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    BB = BN_CTX_get(ctx);
    E = BN_CTX_get(ctx);
    C = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    DA = BN_CTX_get(ctx);
    CB = BN_CTX_get(ctx);

    if (CB == NULL || BN_bin2bn(u, NUM_CHARS_25519, x_1) == NULL
            || BN_copy(x_3, x_1) == NULL || !BN_one(x_2) || !BN_zero(z_2)
            || !BN_one(z_3))
        goto err;

    for (t = NUM_BITS_25519 - 1; t >= 0; t--) {
        k_t = (k[kptr] >> (t % 8)) & 1;
        if ((t % 8) == 0)
            kptr--;
        swap ^= k_t;
        /* Conditional swap */
        cswap(swap, &x_2, &x_3);
        cswap(swap, &z_2, &z_3);
        swap = k_t;

        BN_mod_add(A, x_2, z_2, p25519, ctx);
        BN_mod_sqr(AA, A, p25519, ctx);
        BN_mod_sub(B, x_2, z_2, p25519, ctx);
        BN_mod_sqr(BB, B, p25519, ctx);
        BN_mod_sub(E, AA, BB, p25519, ctx);
        BN_mod_add(C, x_3, z_3, p25519, ctx);
        BN_mod_sub(D, x_3, z_3, p25519, ctx);
        BN_mod_mul(DA, D, A, p25519, ctx);
        BN_mod_mul(CB, C, B, p25519, ctx);
        BN_mod_add(x_3, DA, CB, p25519, ctx);
        BN_mod_sqr(x_3, x_3, p25519, ctx);
        BN_mod_sub(z_3, DA, CB, p25519, ctx);
        BN_mod_sqr(z_3, z_3, p25519, ctx);
        BN_mod_mul(z_3, x_1, z_3, p25519, ctx);
        BN_mod_mul(x_2, AA, BB, p25519, ctx);
        BN_mod_mul(z_2, a24, E, p25519, ctx);
        BN_mod_add(z_2, AA, z_2, p25519, ctx);
        BN_mod_mul(z_2, E, z_2, p25519, ctx);
    }

    /* Conditional swap */
    cswap(swap, &x_2, &x_3);
    cswap(swap, &z_2, &z_3);

    /* We use x_1 as a temp variable here */
    BN_mod_exp(x_1, z_2, pminus2, p25519, ctx);
    BN_mod_mul(x_2, x_2, x_1, p25519, ctx);

    BN_bn2bin(x_2, outtmp);
    BUF_reverse(output, outtmp, NUM_CHARS_25519);
    ret = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

