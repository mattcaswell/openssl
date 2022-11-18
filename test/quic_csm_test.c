/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include "internal/sockets.h"
#include "testutil.h"

static const char msg1[] = "sample.c";

static int test(void)
{
    int testresult = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *net_bio = NULL, *net_bio_own = NULL;
    BIO_ADDR *peer_addr = NULL;
    struct in_addr ina = {0};
    int fd = -1;
    unsigned char alpn[] = {
        15, 'p', 'i', 'c', 'o', 'q', 'u', 'i', 'c', '_', 's', 'a', 'm', 'p',
        'l', 'e'
    };
    unsigned int alpnlen = sizeof(alpn);
    BIO *debugout = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (!TEST_ptr(peer_addr = BIO_ADDR_new()) || !TEST_ptr(debugout))
        goto err;

    ina.s_addr = htonl(0x7f000001UL); /* 127.0.0.1 */

    if (!TEST_true(BIO_ADDR_rawmake(peer_addr, AF_INET,
                                    &ina, sizeof(ina), htons(6121))))
        goto err;

    fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
    if (!TEST_int_ge(fd, 0))
        goto err;

    if (!TEST_true(BIO_socket_nbio(fd, 1)))
        goto err;

    if (!TEST_ptr(net_bio = net_bio_own = BIO_new_dgram(fd, 0)))
        goto err;

    if (!BIO_dgram_set_peer(net_bio, peer_addr))
        goto err;

    if (!TEST_ptr(ctx = SSL_CTX_new(OSSL_QUIC_client_method())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    /* Debug connection logging */
    SSL_set_msg_callback(ssl, SSL_trace);
    SSL_set_msg_callback_arg(ssl, debugout);

    /* SSL_set_alpn_protos() returns 0 on success!!!!!! */
    if (!TEST_false(SSL_set_alpn_protos(ssl, alpn, alpnlen)))
        goto err;

    /* Takes ownership of our reference to the BIO. */
    SSL_set0_rbio(ssl, net_bio);

    /* Get another reference to be transferred in the SSL_set0_wbio call. */
    if (!TEST_true(BIO_up_ref(net_bio))) {
        net_bio_own = NULL; /* SSL_free will free our first reference. */
        goto err;
    }

    SSL_set0_wbio(ssl, net_bio);
    net_bio_own = NULL;

    /* Jump to steady state. */
    fprintf(stderr, "# connecting\n");
    if (!TEST_true(SSL_connect(ssl)))
        goto err;

    fprintf(stderr, "# writing\n");
    if (!TEST_int_eq(SSL_write(ssl, msg1, sizeof(msg1) - 1), (int)sizeof(msg1) - 1))
        goto err;

    for (;;) {
        char msg2[128];
        size_t l = 0;
        memset(msg2, 0, sizeof(msg2));
        if (!SSL_peek_ex(ssl, msg2, sizeof(msg2)-1, &l)) {
            fprintf(stderr, "# not yet\n");
            continue;
        }

        if (l > 0) {
            msg2[l] = '\0';
            fprintf(stderr, "# peek msg: %s\n", msg2);
        } else {
            continue;
        }

        memset(msg2, 0, sizeof(msg2));

        if (!SSL_read_ex(ssl, msg2, sizeof(msg2)-1, &l)) {
            fprintf(stderr, "# not yet\n");
            continue;
        }
        if (l > 0) {
            msg2[l] = '\0';
            fprintf(stderr, "# got msg: %s\n", msg2);
            break;
        }
    }
    //for (;;)
    //    SSL_tick(ssl);

    testresult = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_free(net_bio_own);
    BIO_ADDR_free(peer_addr);
    if (fd >= 0)
        BIO_closesocket(fd);
    BIO_free(debugout);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test);
    return 1;
}
