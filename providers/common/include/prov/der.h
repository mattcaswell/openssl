/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>

/* Well known primitive tags */

#define DER_P_EOC                       0 /* BER End Of Contents tag */
#define DER_P_BOOLEAN                   1
#define DER_P_INTEGER                   2
#define DER_P_BIT_STRING                3
#define DER_P_OCTET_STRING              4
#define DER_P_NULL                      5
#define DER_P_OBJECT                    6
#define DER_P_OBJECT_DESCRIPTOR         7
#define DER_P_EXTERNAL                  8
#define DER_P_REAL                      9
#define DER_P_ENUMERATED               10
#define DER_P_UTF8STRING               12
#define DER_P_SEQUENCE                 16
#define DER_P_SET                      17
#define DER_P_NUMERICSTRING            18
#define DER_P_PRINTABLESTRING          19
#define DER_P_T61STRING                20
#define DER_P_VIDEOTEXSTRING           21
#define DER_P_IA5STRING                22
#define DER_P_UTCTIME                  23
#define DER_P_GENERALIZEDTIME          24
#define DER_P_GRAPHICSTRING            25
#define DER_P_ISO64STRING              26
#define DER_P_GENERALSTRING            27
#define DER_P_UNIVERSALSTRING          28
#define DER_P_BMPSTRING                30

#define DER_F_PRIMITIVE              0x00
#define DER_F_CONSTRUCTED            0x20

#define DER_C_UNIVERSAL              0x00
#define DER_C_APPLICATION            0x40
#define DER_C_CONTEXT                0x80
#define DER_C_NO_CONTEXT            0x100
#define DER_C_PRIVATE                0xC0

/*
 * Run-time constructors.
 *
 * They all construct DER backwards, so care should be taken to use them
 * that way.
 */

#if 0                        /* Example code should not be compiled */

/*
 * Example:
 * To build the RSASSA-PSS AlgorithmIndentifier with the restrictions
 * hashAlgorithm = SHA256, maskGenAlgorithm = mgf1SHA256, saltLength = 20,
 * this is the expected code:
 */

const unsigned char der_oid_mgf1[N]; /* N is to be determined */
const unsigned char der_oid_sha256[M]; /* M is to be determined */
WPACKET pkt;
unsigned char *p;
size_t length;

if (!WPACKET_init_der(&pkt, buf, sizeof(buf))
       /* Start of AlgorithmIdentifier */
    || !DER_w_start_sequence(&pkt)
       /* Start of RSASSA-PSS-params */
    || !DER_w_start_sequence(&pkt)
       /* saltLength */
    || !DER_w_ulong_c(&pkt, 20, 2)
       /* maskGenAlgorithm */
    || !DER_w_precompiled_c(&pkt, der_oid_mgf1, sizeof(der_oid_mgf1), 1)
       /* hashAlgorithm */
    || !DER_w_precompiled_c(&pkt, der_oid_sha256, sizeof(der_oid_sha256), 0)
       /* End of RSASSA-PSS-params */
    || !DER_w_end_sequence(&pkt)

       /* rsassaPss OID */
    || !DER_w_precompiled(&pkt, der_oid_rsassaPss, sizeof(der_oid_rsassaPss))

    || !DER_w_end_sequence(&pkt)
    || !WPACKET_finish(&pkt)
    || !WPACKET_get_total_written(&pkt, &length)
    )
    /* ERROR */ ;
    p = WPACKET_get_curr(&pkt);

/* At this point, |p| is the start of the DER blob and |length| is its length */

#endif

int DER_w_start_context(WPACKET *pkt, int context);

int DER_w_end_context(WPACKET *pkt, int tag, int context);

/*
 * Outputs the DER encoding of a positive ASN.1 INTEGER to pkt.
 *
 * Results in an error if n is negative or too large.
 *
 * Returns 1 on success or 0 on error.
 */
int DER_w_integer_c(WPACKET *pkt, const BIGNUM *n, int context);
int DER_w_integer(WPACKET *pkt, const BIGNUM *n);
int DER_w_ulong_c(WPACKET *pkt, unsigned long v, int context);
int DER_w_ulong(WPACKET *pkt, unsigned long v);

#define DER_w_start_sequence_c(pkt, context) DER_w_start_context(pkt, context)
#define DER_w_start_sequence(pkt) DER_w_start_sequence_c(pkt, DER_C_NO_CONTEXT)

int DER_w_end_sequence_c(WPACKET *pkt, int context);

#define DER_w_end_sequence(pkt) \
    DER_w_end_sequence_c(pkt, DER_C_NO_CONTEXT)

int DER_w_precompiled_c(WPACKET *pkt, unsigned char *data, size_t len,
                        int context);

#define DER_w_precompiled(pkt, data, len) \
    DER_w_precompiled_c(pkt, data, len, DER_C_NO_CONTEXT)
