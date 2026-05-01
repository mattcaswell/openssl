/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "ssl_local.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "internal/ssl_unwrap.h"

void ssl3_cleanup_key_block(SSL_CONNECTION *s)
{
    OPENSSL_clear_free(s->s3.tmp.key_block, s->s3.tmp.key_block_length);
    s->s3.tmp.key_block = NULL;
    s->s3.tmp.key_block_length = 0;
}

int ssl3_init_finished_mac(SSL_CONNECTION *s)
{
    BIO *buf = BIO_new(BIO_s_mem());

    if (buf == NULL) {
        SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_BIO_LIB, "failed to create handshake buffer BIO");
        return 0;
    }
    ssl3_free_digest_list(s);
    s->s3.handshake_buffer = buf;
    (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
    return 1;
}

/*
 * Free digest list. Also frees handshake buffer since they are always freed
 * together.
 */

void ssl3_free_digest_list(SSL_CONNECTION *s)
{
    BIO_free(s->s3.handshake_buffer);
    s->s3.handshake_buffer = NULL;
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst = NULL;
}

int ssl3_finish_mac(SSL_CONNECTION *s, const unsigned char *buf, size_t len)
{
    int ret;

    if (s->s3.handshake_dgst == NULL) {
        /* Note: this writes to a memory BIO so a failure is a fatal error */
        if (len > INT_MAX) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_OVERFLOW, "handshake data too long for BIO write");
            return 0;
        }
        ret = BIO_write(s->s3.handshake_buffer, (void *)buf, (int)len);
        if (ret <= 0 || ret != (int)len) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR, "failed to write handshake data to buffer");
            return 0;
        }
    } else {
        ret = EVP_DigestUpdate(s->s3.handshake_dgst, buf, len);
        if (!ret) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR, "failed to update handshake digest");
            return 0;
        }
    }
    return 1;
}

int ssl3_digest_cached_records(SSL_CONNECTION *s, int keep)
{
    const EVP_MD *md;
    long hdatalen;
    void *hdata;

    if (s->s3.handshake_dgst == NULL) {
        hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
        if (hdatalen <= 0) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_INVALID_LENGTH, "handshake buffer is empty");
            return 0;
        }

        s->s3.handshake_dgst = EVP_MD_CTX_new();
        if (s->s3.handshake_dgst == NULL) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB, "failed to allocate handshake digest context");
            return 0;
        }

        md = ssl_handshake_md(s);
        if (md == NULL) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_NO_MATCH, "no matching digest cached records");
            return 0;
        }
        if (!EVP_DigestInit_ex(s->s3.handshake_dgst, md, NULL)
            || !EVP_DigestUpdate(s->s3.handshake_dgst, hdata, hdatalen)) {
            SSLfatal_data(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR, "failed to initialize or update handshake digest with cached records");
            return 0;
        }
    }
    if (keep == 0) {
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer = NULL;
    }

    return 1;
}
