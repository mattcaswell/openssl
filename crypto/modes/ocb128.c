/* ====================================================================
 * Copyright (c) 2013 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
#include <openssl/crypto.h>
#include "modes_lcl.h"


#ifdef STRICT_ALIGNMENT
typedef struct {unsigned char a[16];} OCB_BLOCK;
#define ocb_block16_xor(in1,in2,out) \
	ocb_block_xor((in1)->a,(in2)->a,16,(out)->a)
#else
typedef struct {u64 a; u64 b;} OCB_BLOCK;
#define ocb_block16_xor(in1,in2,out) \
	(out)->a=(in1)->a^(in2)->a; (out)->b=(in1)->b^(in2)->b;
#endif



/* Calculate the number of binary trailing zero's in any given number */
static u32 ocb_ntz(u64 n)
{
	u32 cnt = 0;

	/* We do a right-to-left simple sequential search. This is surprisingly
	 * efficient as the distribution of trailing zeros is not uniform,
	 * e.g. the number of possible inputs with no trailing zeros is equal to
	 * the number with 1 or more; the number with exactly 1 is equal to the
	 * number with 2 or more, etc. Checking the last two bits covers 75% of
	 * all numbers. Checking the last three covers 87.5%
	 */
	while(!(n & 1)) {
		n >>= 1;
		cnt++;
	}
	return cnt;
}

/* Shift a block of len bytes left by shift bits */
static void ocb_block_lshift(unsigned char *in, size_t len, size_t shift,
		unsigned char *out)
{
	unsigned shift_mask;
	int i;

	shift_mask = 0xff;
	shift_mask <<= (8-shift);

	unsigned char mask[len-2];
	for(i=len-1; i>=0; i--) {
		if(i>0) {
			mask[i-1] = in[i] & shift_mask;
			mask[i-1] >>= 8-shift;
		}
		out[i] = in[i] << shift;

		if(i != len - 1) {
			out[i] ^= mask[i];
		}
	}
}

/* Perform a "double" operation as per OCB spec */
static void ocb_double(unsigned char *in, unsigned char *out)
{
	unsigned char mask;

	/* Calculate the mask based on the most significant bit. There are more
	 * efficient ways to do this - but this way is constant time */
	mask = in[0] & 0x80;
	mask >>= 7;
	mask *= 135;

	ocb_block_lshift(in, 16, 1, out);

	out[15] ^= mask;
}

/* Perform an xor on in1 and in2 blocks - each of len bytes. Store result in
 * out */
static void ocb_block_xor(const unsigned char *in1,
		const unsigned char *in2, size_t len, unsigned char *out)
{
	int i;

	for(i=0; i<len; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}


/* Lookup L_index in our lookup table. If we haven't already got it we need to
 * calculate it */
static unsigned char *ocb_lookup_l(OCB128_CONTEXT *ctx, size_t index)
{
	if(index <= ctx->l_index) {
		return ctx->l+(index*16);
	}

	/* We don't have it - so calculate it */
	ocb_double(ctx->l+((index-1)*16),ctx->l+(index*16));
	ctx->l_index++;
	return ctx->l+(index*16);
}

/* Create a new OCB128_CONTEXT */
OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec,
		block128_f encrypt, block128_f decrypt)
{
	OCB128_CONTEXT *ret;

	if ((ret = (OCB128_CONTEXT *)OPENSSL_malloc(sizeof(OCB128_CONTEXT))))
		CRYPTO_ocb128_init(ret,keyenc,keydec,encrypt,decrypt);

	return ret;
}

/* Initialise an existing OCB128_CONTEXT */
void CRYPTO_ocb128_init(OCB128_CONTEXT *ctx,void *keyenc, void *keydec,
		block128_f encrypt,block128_f decrypt)
{
	/* Clear everything to NULLs */
	memset(ctx,0,sizeof(*ctx));

	/* We set both the encryption and decryption key schedules - decryption
	 * needs both. Don't really need decryption schedule if only doing
	 * encryption - but it simplifies things to take it anyway */
	ctx->encrypt = encrypt;
	ctx->decrypt = decrypt;
	ctx->keyenc  = keyenc;
	ctx->keydec  = keydec;

	/* L_* = ENCIPHER(K, zeros(128)) */
	ctx->encrypt(ctx->l_star, ctx->l_star, ctx->keyenc);

	/* L_$ = double(L_*) */
	ocb_double(ctx->l_star, ctx->l_dollar);

	/* L_0 = double(L_$) */
	ocb_double(ctx->l_dollar, ctx->l);
	ctx->l_index = 0;
}

void CRYPTO_ocb128_set_ks(OCB128_CONTEXT *ctx, void *keyenc, void *keydec)
{
	ctx->keyenc = keyenc;
	ctx->keydec = keydec;
}

/* Set the IV to be used for this operation. Must be 1 - 15 bytes.
 */
int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
			size_t len, size_t taglen)
{
	unsigned char ktop[16], tmp[16], mask;
	unsigned char stretch[24], nonce[16];
	size_t bottom, shift;

	/* Spec says IV is 120 bits or fewer - it allows non byte aligned lengths.
	 * We don't support  this at this stage */
	if((len >15) || (len < 1) || (taglen > 16) || (taglen < 1)) {
		return -1;
	}

	/* Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N */
	nonce[0] = ((taglen*8) % 128) << 1;
	memset(nonce+1, 0, 15);
	memcpy(nonce+16-len, iv, len);
	nonce[15-len] |= 1;

	/* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
	memcpy(tmp, nonce, 16);
	tmp[15] &= 0xc0;
	ctx->encrypt(tmp, ktop, ctx->keyenc);

	/* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
	memcpy(stretch, ktop, 16);
	ocb_block_xor(ktop, ktop+1, 8, stretch+16);

	/* bottom = str2num(Nonce[123..128]) */
	bottom = nonce[15] & 0x3f;

	/* Offset_0 = Stretch[1+bottom..128+bottom] */
	shift = bottom % 8;
	ocb_block_lshift(stretch+(bottom/8), 16, shift, ctx->offset);
	mask = 0xff;
	mask <<= 8-shift;
	ctx->offset[15] |= (*(stretch+(bottom/8)+16) & mask) >> (8 - shift);

	return 1;
}

/* Provide any AAD. This can be called multiple times. Only the final time can
 * have a partial block
 */
void CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad,
			size_t len)
{
	u64 all_num_blocks, num_blocks;
	u64 i;
	OCB_BLOCK tmp1;
	OCB_BLOCK tmp2;
	int last_len;

	/* Calculate the number of blocks of AAD provided now, and so far */
	num_blocks = len / 16;
	all_num_blocks = num_blocks + ctx->blocks_hashed;

	OCB_BLOCK *offset_aad = (OCB_BLOCK *)(ctx->offset_aad);

	/* Loop through all full blocks of AAD */
	for(i=ctx->blocks_hashed+1; i<=all_num_blocks; i++) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		OCB_BLOCK *lookup = (OCB_BLOCK *)ocb_lookup_l(ctx, ocb_ntz(i));
		ocb_block16_xor(offset_aad, lookup, offset_aad);

		/* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
		OCB_BLOCK *aad_block = (OCB_BLOCK *)(aad+((i-ctx->blocks_hashed-1)*16));
		ocb_block16_xor(offset_aad, aad_block, &tmp1);
		ctx->encrypt((unsigned char *)&tmp1, (unsigned char *)&tmp2,
				ctx->keyenc);
		ocb_block16_xor((OCB_BLOCK *)(ctx->sum), &tmp2,
				(OCB_BLOCK *)(ctx->sum));
	}

	/* Check if we have any partial blocks left over. This is only valid in the
	 * last call to this function
	 */
	last_len = len % 16;

	if(last_len > 0) {
		/* Offset_* = Offset_m xor L_* */
		ocb_block16_xor(offset_aad, (OCB_BLOCK *)(ctx->l_star), offset_aad);

		/* CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
		memset((void *)&tmp1,0,16);
		memcpy((void *)&tmp1, aad+(num_blocks*16), last_len);
		((unsigned char *)&tmp1)[last_len] = 0x80;
		ocb_block16_xor(offset_aad, &tmp1, &tmp2);

		/* Sum = Sum_m xor ENCIPHER(K, CipherInput) */
		ctx->encrypt((unsigned char *)&tmp2, (unsigned char *)&tmp1,
				ctx->keyenc);
		ocb_block16_xor((OCB_BLOCK *)(ctx->sum), &tmp1,
				(OCB_BLOCK *)(ctx->sum));
	}

	ctx->blocks_hashed = all_num_blocks;
}

/* Provide any data to be encrypted. This can be called multiple times. Only
 * the final time can have a partial block
 */
void CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	u64 i;
	u64 all_num_blocks, num_blocks;
	OCB_BLOCK tmp1;
	OCB_BLOCK tmp2;
	unsigned char pad[16];
	int last_len;

	/* Calculate the number of blocks of data to be encrypted provided now, and
	 * so far */
	num_blocks = len / 16;
	all_num_blocks = num_blocks + ctx->blocks_processed;

	OCB_BLOCK *checksum = (OCB_BLOCK *)(ctx->checksum);
	OCB_BLOCK *offset = (OCB_BLOCK *)(ctx->offset);

	/* Loop through all full blocks to be encrypted */
	for(i=ctx->blocks_processed+1; i<=all_num_blocks; i++) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		OCB_BLOCK *lookup = (OCB_BLOCK *)ocb_lookup_l(ctx, ocb_ntz(i));
		ocb_block16_xor(offset, lookup, offset);

		/* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
		OCB_BLOCK *inblock = (OCB_BLOCK *)(in+((i-ctx->blocks_processed-1)*16));
		ocb_block16_xor(offset, inblock, &tmp1);
		ctx->encrypt((unsigned char *)&tmp1, (unsigned char *)&tmp2,
				ctx->keyenc);
		OCB_BLOCK *outblock =
				(OCB_BLOCK *)(out+((i-ctx->blocks_processed-1)*16));
		ocb_block16_xor(offset, &tmp2, outblock);

		/* Checksum_i = Checksum_{i-1} xor P_i */
		ocb_block16_xor(checksum, inblock, checksum);
	}


	/* Check if we have any partial blocks left over. This is only valid in the
	 * last call to this function
	 */
	last_len = len % 16;

	if(last_len > 0) {
		/* Offset_* = Offset_m xor L_* */
		ocb_block16_xor(offset, (OCB_BLOCK *)(ctx->l_star), offset);

		/* Pad = ENCIPHER(K, Offset_*) */
		ctx->encrypt(ctx->offset, pad, ctx->keyenc);

		/* C_* = P_* xor Pad[1..bitlen(P_*)] */
		ocb_block_xor(in+(len/16)*16, pad, last_len, out+(num_blocks*16));

		/* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
		memset((void *)&tmp1, 0, 16);
		memcpy((void *)&tmp1, in+(len/16)*16, last_len);
		((unsigned char *)(&tmp1))[last_len] = 0x80;
		ocb_block16_xor(checksum, &tmp1, checksum);
	}

	ctx->blocks_processed = all_num_blocks;
}

/* Provide any data to be decrypted. This can be called multiple times. Only
 * the final time can have a partial block
 */
void CRYPTO_ocb128_decrypt(OCB128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	u64 i;
	u64 all_num_blocks, num_blocks;
	OCB_BLOCK tmp1;
	OCB_BLOCK tmp2;
	unsigned char pad[16];
	int last_len;

	/* Calculate the number of blocks of data to be decrypted provided now, and
	 * so far */
	num_blocks = len / 16;
	all_num_blocks = num_blocks + ctx->blocks_processed;

	OCB_BLOCK *offset = (OCB_BLOCK *)(ctx->offset);
	OCB_BLOCK *checksum = (OCB_BLOCK *)(ctx->checksum);

	/* Loop through all full blocks to be decrypted */
	for(i=ctx->blocks_processed+1; i<=all_num_blocks; i++) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		OCB_BLOCK *lookup = (OCB_BLOCK *)ocb_lookup_l(ctx, ocb_ntz(i));
		ocb_block16_xor(offset, lookup, offset);

		/* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
		OCB_BLOCK *inblock =
				(OCB_BLOCK *)(in+((i-ctx->blocks_processed-1)*16));
		ocb_block16_xor(offset, inblock, &tmp1);
		ctx->decrypt((unsigned char *)&tmp1,
				(unsigned char *)&tmp2, ctx->keydec);
		OCB_BLOCK *outblock =
				(OCB_BLOCK *)(out+((i-ctx->blocks_processed-1)*16));
		ocb_block16_xor(offset, &tmp2, outblock);

		/* Checksum_i = Checksum_{i-1} xor P_i */
		ocb_block16_xor(checksum, outblock, checksum);
	}

	/* Check if we have any partial blocks left over. This is only valid in the
	 * last call to this function
	 */
	last_len = len % 16;

	if(last_len > 0) {
		/* Offset_* = Offset_m xor L_* */
		ocb_block16_xor(offset, (OCB_BLOCK *)(ctx->l_star), offset);

		/* Pad = ENCIPHER(K, Offset_*) */
		ctx->encrypt(ctx->offset, pad, ctx->keyenc);

		/* P_* = C_* xor Pad[1..bitlen(C_*)] */
		ocb_block_xor(in+(len/16)*16, pad, last_len, out+(num_blocks*16));

		/* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
		memset((void *)&tmp1, 0, 16);
		memcpy((void *)&tmp1, out+(len/16)*16, last_len);
		((unsigned char *)(&tmp1))[last_len] = 0x80;
		ocb_block16_xor(checksum, &tmp1, checksum);
	}

	ctx->blocks_processed = all_num_blocks;
}

/* Calculate the tag and verify it against the supplied tag */
int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx,const unsigned char *tag,
			size_t len)
{
	OCB_BLOCK tmp1, tmp2;

	/*Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A) */
	ocb_block16_xor((OCB_BLOCK *)(ctx->checksum),
			(OCB_BLOCK *)(ctx->offset), &tmp1);
	ocb_block16_xor(&tmp1, (OCB_BLOCK *)(ctx->l_dollar), &tmp2);
	ctx->encrypt((void *)&tmp2, (void *)&tmp1, ctx->keyenc);
	ocb_block16_xor(&tmp1, (OCB_BLOCK *)(ctx->sum),
			(OCB_BLOCK *)(ctx->tag));

	if(len > 16 || len < 1) {
		return -1;
	}

	/* Compare the tag if we've been given one */
	if (tag)
		return CRYPTO_memcmp(ctx->tag,tag,len);
	else
		return -1;
}

/* Retrieve the calculated tag */
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
	if(len > 16 || len < 1) {
		return -1;
	}

	/* Calculate the tag */
	CRYPTO_ocb128_finish(ctx, NULL, 0);

	/* Copy the tag into the supplied buffer */
	memcpy(tag, ctx->tag, len);

	return 1;
}

/* Release all resources */
void CRYPTO_ocb128_release(OCB128_CONTEXT *ctx)
{
	if (ctx) {
		OPENSSL_cleanse(ctx,sizeof(*ctx));
		OPENSSL_free(ctx);
	}
}
