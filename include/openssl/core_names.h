/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CORE_NAMES_H
# define OSSL_CORE_NAMES_H

# ifdef __cplusplus
extern "C" {
# endif

/*
 * Well known parameter names that Providers can define
 */

/*
 * A printable name for this provider
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_NAME        "name"
/*
 * A version string for this provider
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_VERSION     "version"
/*
 * A string providing provider specific build information
 * Type: OSSL_PARAM_UTF8_STRING
 */
#define OSSL_PROV_PARAM_BUILDINFO   "buildinfo"


/* Well known cipher parameters */

#define OSSL_CIPHER_PARAM_PADDING   "padding"
#define OSSL_CIPHER_PARAM_MODE      "mode"

/* digest parameters */
#define OSSL_DIGEST_PARAM_XOFLEN    "xoflen"
#define OSSL_DIGEST_PARAM_SSL3_MS   "ssl3-ms"
#define OSSL_DIGEST_PARAM_PAD_TYPE  "pad_type"
#define OSSL_DIGEST_PARAM_MICALG    "micalg"

/* PKEY parameters */
/* Diffie-Hellman Parameters */
#define OSSL_PKEY_PARAM_PKEY_DH_P         "pkey-dh-p"
#define OSSL_PKEY_PARAM_PKEY_DH_G         "pkey-dh-g"
#define OSSL_PKEY_PARAM_PKEY_DH_Q         "pkey-dh-q"
/* Diffie-Hellman Keys */
#define OSSL_PKEY_PARAM_PKEY_DH_PUB_KEY   "pkey-dh-pub"
#define OSSL_PKEY_PARAM_PKEY_DH_PRIV_KEY  "pkey-dh-priv"

# ifdef __cplusplus
}
# endif

#endif
