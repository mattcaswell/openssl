/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * A simple ASN.1 DER encoder/decoder for DSA-Sig-Value and ECDSA-Sig-Value.
 *
 * DSA-Sig-Value ::= SEQUENCE {
 *  r  INTEGER,
 *  s  INTEGER
 * }
 *
 * ECDSA-Sig-Value ::= SEQUENCE {
 *  r  INTEGER,
 *  s  INTEGER
 * }
 */

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "crypto/asn1_dsa.h"
#include "internal/packet.h"
#include "prov/der.h"

/*
 * Outputs the DER encoding of a DSA-Sig-Value or ECDSA-Sig-Value to pkt. pkt
 * may be initialised with a NULL buffer which enables pkt to be used to
 * calculate how many bytes would be needed.
 *
 * Returns 1 on success or 0 on error.
 */
int encode_der_dsa_sig(WPACKET *pkt, const BIGNUM *r, const BIGNUM *s)
{
    if (!DER_w_start_sequence(pkt)
            || !DER_w_integer(pkt, s)
            || !DER_w_integer(pkt, r)
            || !DER_w_end_sequence(pkt))
        return 0;

    return 1;
}

/*
 * Decodes the DER length octets in pkt and initialises subpkt with the
 * following bytes of that length.
 *
 * Returns 1 on success or 0 on failure.
 */
static int decode_der_length(PACKET *pkt, PACKET *subpkt)
{
    unsigned int byte;

    if (!PACKET_get_1(pkt, &byte))
        return 0;

    if (byte < 0x80)
        return PACKET_get_sub_packet(pkt, subpkt, (size_t)byte);
    if (byte == 0x81)
        return PACKET_get_length_prefixed_1(pkt, subpkt);
    if (byte == 0x82)
        return PACKET_get_length_prefixed_2(pkt, subpkt);

    /* Too large, invalid, or not DER. */
    return 0;
}

/*
 * Decodes a single ASN.1 INTEGER value from pkt, which must be DER encoded,
 * and updates n with the decoded value.
 *
 * The BIGNUM, n, must have already been allocated by calling BN_new().
 * pkt must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns 1 on success or 0 on error.
 *
 * If the PACKET is supposed to only contain a single INTEGER value with no
 * trailing garbage then it is up to the caller to verify that all bytes
 * were consumed.
 */
static int decode_der_integer(PACKET *pkt, BIGNUM *n)
{
    PACKET contpkt, tmppkt;
    unsigned int tag, tmp;

    /* Check we have an integer and get the content bytes */
    if (!PACKET_get_1(pkt, &tag)
            || tag != DER_P_INTEGER
            || !decode_der_length(pkt, &contpkt))
        return 0;

    /* Peek ahead at the first bytes to check for proper encoding */
    tmppkt = contpkt;
    /* The INTEGER must be positive */
    if (!PACKET_get_1(&tmppkt, &tmp)
            || (tmp & 0x80) != 0)
        return 0;
    /* If there a zero padding byte the next byte must have the msb set */
    if (PACKET_remaining(&tmppkt) > 0 && tmp == 0) {
        if (!PACKET_get_1(&tmppkt, &tmp)
                || (tmp & 0x80) == 0)
            return 0;
    }

    if (BN_bin2bn(PACKET_data(&contpkt),
                  (int)PACKET_remaining(&contpkt), n) == NULL)
        return 0;

    return 1;
}

/*
 * Decodes a single DSA-Sig-Value or ECDSA-Sig-Value from *ppin, which must be
 * DER encoded, updates r and s with the decoded values, and increments *ppin
 * past the data that was consumed.
 *
 * The BIGNUMs, r and s, must have already been allocated by calls to BN_new().
 * ppin and *ppin must not be NULL.
 *
 * An attempt to consume more than len bytes results in an error.
 * Returns the number of bytes of input consumed or 0 if an error occurs.
 *
 * If the buffer is supposed to only contain a single [EC]DSA-Sig-Value with no
 * trailing garbage then it is up to the caller to verify that all bytes
 * were consumed.
 */
size_t decode_der_dsa_sig(BIGNUM *r, BIGNUM *s, const unsigned char **ppin,
                          size_t len)
{
    size_t consumed;
    PACKET pkt, contpkt;
    unsigned int tag;

    if (!PACKET_buf_init(&pkt, *ppin, len)
            || !PACKET_get_1(&pkt, &tag)
            || tag != DER_P_SEQUENCE
            || !decode_der_length(&pkt, &contpkt)
            || !decode_der_integer(&contpkt, r)
            || !decode_der_integer(&contpkt, s)
            || PACKET_remaining(&contpkt) != 0)
        return 0;

    consumed = PACKET_data(&pkt) - *ppin;
    *ppin += consumed;
    return consumed;
}

