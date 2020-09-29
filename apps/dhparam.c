/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/decoder.h>

#define DEFBITS 2048

static EVP_PKEY *dsa_to_dh(EVP_PKEY *dh);
static int gendh_cb(EVP_PKEY_CTX *ctx);

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT,
    OPT_ENGINE, OPT_CHECK, OPT_TEXT, OPT_NOOUT,
    OPT_DSAPARAM, OPT_C, OPT_2, OPT_3, OPT_5,
    OPT_R_ENUM, OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS dhparam_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [numbits]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"check", OPT_CHECK, '-', "Check the DH parameters"},
#ifndef OPENSSL_NO_DSA
    {"dsaparam", OPT_DSAPARAM, '-',
     "Read or generate DSA parameters, convert to DH"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device"},
#endif

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format, DER or PEM"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"outform", OPT_OUTFORM, 'F', "Output format, DER or PEM"},
    {"text", OPT_TEXT, '-', "Print a text form of the DH parameters"},
    {"noout", OPT_NOOUT, '-', "Don't output any DH parameters"},
    {"C", OPT_C, '-', "Print C code"},
    {"2", OPT_2, '-', "Generate parameters using 2 as the generator value"},
    {"3", OPT_3, '-', "Generate parameters using 3 as the generator value"},
    {"5", OPT_5, '-', "Generate parameters using 5 as the generator value"},

    OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,

    OPT_PARAMETERS(),
    {"numbits", 0, 0, "Number of bits if generating parameters (optional)"},
    {NULL}
};

int dhparam_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    DH *dh = NULL, *alloc_dh = NULL;
    EVP_PKEY *pkey = NULL, *tmppkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *infile = NULL, *outfile = NULL, *prog;
    ENGINE *e = NULL;
#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
    int dsaparam = 0;
#endif
    int i, text = 0, C = 0, ret = 1, num = 0, g = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, check = 0, noout = 0;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, dhparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(dhparam_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_CHECK:
            check = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_DSAPARAM:
# ifdef OPENSSL_NO_DEPRECATED_3_0
            BIO_printf(bio_err, "The dsaparam option is deprecated.\n");
# else
            dsaparam = 1;
# endif
            break;
        case OPT_C:
            C = 1;
            break;
        case OPT_2:
            g = 2;
            break;
        case OPT_3:
            g = 3;
            break;
        case OPT_5:
            g = 5;
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argv[0] != NULL && (!opt_int(argv[0], &num) || num <= 0))
        goto end;

    if (g && !num)
        num = DEFBITS;

    if (dsaparam && g) {
        BIO_printf(bio_err,
                   "Error, generator may not be chosen for DSA parameters\n");
        goto end;
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    /* DH parameters */
    if (num && !g)
        g = 2;

    if (num) {
        const char *alg = dsaparam ? "DSA" : "DH";

        ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
        if (ctx == NULL) {
            BIO_printf(bio_err,
                        "Error, %s param generation context allocation failed\n",
                        alg);
            goto end;
        }
        EVP_PKEY_CTX_set_cb(ctx, gendh_cb);
        EVP_PKEY_CTX_set_app_data(ctx, bio_err);
        BIO_printf(bio_err,
                    "Generating %s parameters, %d bit long %sprime\n",
                    alg, num, dsaparam ? "" : "safe ");

        if (!EVP_PKEY_paramgen_init(ctx)) {
            BIO_printf(bio_err,
                        "Error, unable to initialise %s parameters\n",
                        alg);
            goto end;
        }

        if (dsaparam) {
            if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, num)) {
                BIO_printf(bio_err, "Error, unable to set DSA prime length\n");
                goto end;
            }
        } else {
            if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, num)) {
                BIO_printf(bio_err, "Error, unable to set DH prime length\n");
                goto end;
            }
        }

        if (!EVP_PKEY_paramgen(ctx, &tmppkey)) {
            BIO_printf(bio_err, "Error, %s generation failed\n", alg);
            goto end;
        }

        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        if (dsaparam) {
            pkey = dsa_to_dh(tmppkey);
            if (pkey == NULL)
                goto end;
            EVP_PKEY_free(tmppkey);
        } else {
            pkey = tmppkey;
        }
        tmppkey = NULL;
    } else {
        OSSL_DECODER_CTX *decoderctx = NULL;

        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

        decoderctx
            = OSSL_DECODER_CTX_new_by_EVP_PKEY(&tmppkey,
                                                (informat == FORMAT_ASN1)
                                                ? "DER" : NULL, 
                                                NULL, NULL);
        if (decoderctx == NULL
                || !OSSL_DECODER_from_bio(decoderctx, in)) {
            OSSL_DECODER_CTX_free(decoderctx);
            BIO_printf(bio_err, "Error, unable to load parameters\n");
            goto end;
        }
        OSSL_DECODER_CTX_free(decoderctx);

        if (tmppkey == NULL) {
            BIO_printf(bio_err, "Error, unable to load parameters\n");
            goto end;
        }
        if (dsaparam) {
            if (!EVP_PKEY_is_a(tmppkey, "DSA")) {
                BIO_printf(bio_err, "Error, unable to load DSA parameters\n");
                goto end;
            }
            pkey = dsa_to_dh(tmppkey);
            if (pkey == NULL)
                goto end;
        } else {
            if (!EVP_PKEY_is_a(tmppkey, "DH")
                    && !EVP_PKEY_is_a(tmppkey, "DHX")) {
                BIO_printf(bio_err, "Error, unable to load DH parameters\n");
                goto end;
            }
            pkey = tmppkey;
            tmppkey = NULL;
        }
    }

    if (text)
        EVP_PKEY_print_params(out, pkey, 4, NULL);

    if (check) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (ctx == NULL) {
            BIO_printf(bio_err, "Error, failed to check DH parameters\n");
            goto end;
        }
        if (!EVP_PKEY_param_check(ctx) /* DH_check(dh, &i) */) {
            BIO_printf(bio_err, "Error, invalid parameters generated\n");
            goto end;
        }
        BIO_printf(bio_err, "DH parameters appear to be ok.\n");
        if (num != 0) {
            /*
             * We have generated parameters but DH_check() indicates they are
             * invalid! This should never happen!
             */
            BIO_printf(bio_err, "Error, invalid parameters generated\n");
            goto end;
        }
    }
    if (C) {
        unsigned char *data;
        int len, bits;
        const BIGNUM *pbn, *gbn;

        dh = EVP_PKEY_get0_DH(pkey);
        len = EVP_PKEY_size(pkey);
        bits = EVP_PKEY_size(pkey);
        DH_get0_pqg(dh, &pbn, NULL, &gbn);
        data = app_malloc(len, "print a BN");

        BIO_printf(out, "static DH *get_dh%d(void)\n{\n", bits);
        print_bignum_var(out, pbn, "dhp", bits, data);
        print_bignum_var(out, gbn, "dhg", bits, data);
        BIO_printf(out, "    DH *dh = DH_new();\n"
                        "    BIGNUM *p, *g;\n"
                        "\n"
                        "    if (dh == NULL)\n"
                        "        return NULL;\n");
        BIO_printf(out, "    p = BN_bin2bn(dhp_%d, sizeof(dhp_%d), NULL);\n",
                   bits, bits);
        BIO_printf(out, "    g = BN_bin2bn(dhg_%d, sizeof(dhg_%d), NULL);\n",
                   bits, bits);
        BIO_printf(out, "    if (p == NULL || g == NULL\n"
                        "            || !DH_set0_pqg(dh, p, NULL, g)) {\n"
                        "        DH_free(dh);\n"
                        "        BN_free(p);\n"
                        "        BN_free(g);\n"
                        "        return NULL;\n"
                        "    }\n");
        if (DH_get_length(dh) > 0)
            BIO_printf(out,
                        "    if (!DH_set_length(dh, %ld)) {\n"
                        "        DH_free(dh);\n"
                        "        return NULL;\n"
                        "    }\n", DH_get_length(dh));
        BIO_printf(out, "    return dh;\n}\n");
        OPENSSL_free(data);
    }

    if (!noout) {
        const BIGNUM *q;
        /* Temporary: FIXME */
        dh = EVP_PKEY_get0_DH(pkey);
        DH_get0_pqg(dh, NULL, &q, NULL);
        if (outformat == FORMAT_ASN1) {
            if (q != NULL)
                i = ASN1_i2d_bio_of(DH, i2d_DHxparams, out, dh);
            else
                i = ASN1_i2d_bio_of(DH, i2d_DHparams, out, dh);
        } else if (q != NULL) {
            i = PEM_write_bio_DHxparams(out, dh);
        } else {
            i = PEM_write_bio_DHparams(out, dh);
        }
        if (!i) {
            BIO_printf(bio_err, "Error, unable to write DH parameters\n");
            goto end;
        }
    }
    ret = 0;
 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    DH_free(alloc_dh);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(tmppkey);
    EVP_PKEY_CTX_free(ctx);
    release_engine(e);
    return ret;
}

/*
 * Historically we had the low level call DSA_dup_DH() to do this.
 * That is now deprecated with no replacement. Since we still need to do this
 * for backwards compatibility reasons, we do it "manually".
 */
static EVP_PKEY *dsa_to_dh(EVP_PKEY *dh)
{
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &bn_p)
            || !EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_Q, &bn_q)
            || !EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_G, &bn_g)) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL
            || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P,
                                        bn_p)
            || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q,
                                        bn_q)
            || !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G,
                                        bn_g)
            || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);
    if (ctx == NULL
            || !EVP_PKEY_param_fromdata_init(ctx)
            || !EVP_PKEY_fromdata(ctx, &pkey, params)) {
        BIO_printf(bio_err, "Error, failed to set DH parameters\n");
        goto err;
    }

 err:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free_params(params);
    OSSL_PARAM_BLD_free(tmpl);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_g);
    return pkey;
}

static int gendh_cb(EVP_PKEY_CTX *ctx)
{
    int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    static const char symbols[] = ".+*\n";
    char c = (p >= 0 && (size_t)p < sizeof(symbols) - 1) ? symbols[p] : '?';

    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
    return 1;
}
