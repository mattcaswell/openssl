#include <openssl/bn.h>
#include "internal/packet.h"
#include "prov/der.h"

int DER_w_start_context(WPACKET *pkt, int context)
{
    if ((context != DER_C_NO_CONTEXT && !WPACKET_start_sub_packet(pkt))
            || !WPACKET_start_sub_packet(pkt))
        return 0;

    return 1;
}

int DER_w_end_context(WPACKET *pkt, int tag, int context)
{
    if (!WPACKET_close(pkt)
            || !WPACKET_put_bytes_u8(pkt, tag))
        return 0;

    if (context != DER_C_NO_CONTEXT) {
        if (!WPACKET_close(pkt)
                || !WPACKET_put_bytes_u8(pkt, DER_C_CONTEXT | context))
            return 0;
    }

    return 1;
}

/*
 * Outputs the DER encoding of a positive ASN.1 INTEGER to pkt.
 *
 * Results in an error if n is negative or too large.
 *
 * Returns 1 on success or 0 on error.
 */
int DER_w_integer_c(WPACKET *pkt, const BIGNUM *n, int context)
{
    unsigned char *bnbytes;
    size_t cont_len;

    if (BN_is_negative(n))
        return 0;

    /*
     * Calculate the ASN.1 INTEGER DER content length for n.
     * This is the number of whole bytes required to represent n (i.e. rounded
     * down), plus one.
     * If n is zero then the content is a single zero byte (length = 1).
     * If the number of bits of n is a multiple of 8 then an extra zero padding
     * byte is included to ensure that the value is still treated as positive
     * in the INTEGER two's complement representation.
     */
    cont_len = BN_num_bits(n) / 8 + 1;

    if (!DER_w_start_context(pkt, context)
            || !WPACKET_allocate_bytes(pkt, cont_len, &bnbytes)
            || !WPACKET_close(pkt)
            || !DER_w_end_context(pkt, DER_P_INTEGER, context))
        return 0;

    if (bnbytes != NULL
            && BN_bn2binpad(n, bnbytes, (int)cont_len) != (int)cont_len)
        return 0;

    return 1;
}

int DER_w_integer(WPACKET *pkt, const BIGNUM *n)
{
    return DER_w_integer_c(pkt, n, DER_C_NO_CONTEXT);
}

int DER_w_ulong_c(WPACKET *pkt, unsigned long v, int context)
{
    size_t n = 0;
    unsigned char ch;

    if (!DER_w_start_context(pkt, context))
        return 0;

    while (v != 0) {
        ch = (unsigned char)(v & 0xFF);
        if (!WPACKET_put_bytes_u8(pkt, ch))
            return 0;
        n++;
        v >>= 8;
    }
    if (n == 0 || (ch > 0x7F)) {
        if (!WPACKET_put_bytes_u8(pkt, 0))
            return 0;
        n++;
    }

    if (!DER_w_end_context(pkt, DER_P_INTEGER, context))
        return 0;

    return 1;
}

int DER_w_ulong(WPACKET *pkt, unsigned long v)
{
    return DER_w_ulong_c(pkt, v, DER_C_NO_CONTEXT);
}

int DER_w_end_sequence_c(WPACKET *pkt, int context)
{
    if (!WPACKET_close(pkt)
            || !WPACKET_put_bytes_u8(pkt, DER_P_SEQUENCE))
        return 0;

    return 1;
}

int DER_w_precompiled_c(WPACKET *pkt, unsigned char *data, size_t len,
                        int context)
{
    if ((context != DER_C_NO_CONTEXT && !WPACKET_start_sub_packet(pkt)))
        return 0;

    if (!WPACKET_memcpy(pkt, data, len))

    if ((context != DER_C_NO_CONTEXT && !WPACKET_close(pkt)))
        return 0;

    return 1;
}
