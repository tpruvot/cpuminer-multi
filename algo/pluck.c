/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler, 2015 Jordan Earls
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdlib.h>
#include <string.h>

#define BLOCK_HEADER_SIZE 80

// windows
#ifndef htobe32
#define htobe32(x)  ((uint32_t)htonl((uint32_t)(x)))
#endif

#ifdef _MSC_VER
#define ROTL(a, b) _rotl(a,b)
#define ROTR(a, b) _rotr(a,b)
#else
#define ROTL(a, b) (((a) << b) | ((a) >> (32 - b)))
#define ROTR(a, b) ((a >> b) | (a << (32 - b)))
#endif

#if defined(_MSC_VER) && defined(_M_X64)
#define _VECTOR __vectorcall
#include <intrin.h>
//#include <emmintrin.h> //SSE2
//#include <pmmintrin.h> //SSE3
//#include <tmmintrin.h> //SSSE3
//#include <smmintrin.h> //SSE4.1
//#include <nmmintrin.h> //SSE4.2
//#include <ammintrin.h> //SSE4A
//#include <wmmintrin.h> //AES
//#include <immintrin.h> //AVX
#define OPT_COMPATIBLE
#elif defined(__GNUC__) && defined(__x86_64__)
#include <x86intrin.h>
#define _VECTOR
#endif

#ifdef OPT_COMPATIBLE
static void _VECTOR xor_salsa8(__m128i B[4], const __m128i Bx[4], int i)
{
	__m128i X0, X1, X2, X3;

	if (i <= 128) {
		// a xor 0 = a
		X0 = B[0] = Bx[0];
		X1 = B[1] = Bx[1];
		X2 = B[2] = Bx[2];
		X3 = B[3] = Bx[3];
	} else {
		X0 = B[0] = _mm_xor_si128(B[0], Bx[0]);
		X1 = B[1] = _mm_xor_si128(B[1], Bx[1]);
		X2 = B[2] = _mm_xor_si128(B[2], Bx[2]);
		X3 = B[3] = _mm_xor_si128(B[3], Bx[3]);
	}

	for (i = 0; i < 4; i++) {
		/* Operate on columns. */
		X1.m128i_u32[0] ^= ROTL(X0.m128i_u32[0] + X3.m128i_u32[0], 7);
		X2.m128i_u32[1] ^= ROTL(X1.m128i_u32[1] + X0.m128i_u32[1], 7);
		X3.m128i_u32[2] ^= ROTL(X2.m128i_u32[2] + X1.m128i_u32[2], 7);
		X0.m128i_u32[3] ^= ROTL(X3.m128i_u32[3] + X2.m128i_u32[3], 7);

		X2.m128i_u32[0] ^= ROTL(X1.m128i_u32[0] + X0.m128i_u32[0], 9);
		X3.m128i_u32[1] ^= ROTL(X2.m128i_u32[1] + X1.m128i_u32[1], 9);
		X0.m128i_u32[2] ^= ROTL(X3.m128i_u32[2] + X2.m128i_u32[2], 9);
		X1.m128i_u32[3] ^= ROTL(X0.m128i_u32[3] + X3.m128i_u32[3], 9);

		X3.m128i_u32[0] ^= ROTL(X2.m128i_u32[0] + X1.m128i_u32[0], 13);
		X0.m128i_u32[1] ^= ROTL(X3.m128i_u32[1] + X2.m128i_u32[1], 13);
		X1.m128i_u32[2] ^= ROTL(X0.m128i_u32[2] + X3.m128i_u32[2], 13);
		X2.m128i_u32[3] ^= ROTL(X1.m128i_u32[3] + X0.m128i_u32[3], 13);

		X0.m128i_u32[0] ^= ROTL(X3.m128i_u32[0] + X2.m128i_u32[0], 18);
		X1.m128i_u32[1] ^= ROTL(X0.m128i_u32[1] + X3.m128i_u32[1], 18);
		X2.m128i_u32[2] ^= ROTL(X1.m128i_u32[2] + X0.m128i_u32[2], 18);
		X3.m128i_u32[3] ^= ROTL(X2.m128i_u32[3] + X1.m128i_u32[3], 18);

		/* Operate on rows. */
		X0.m128i_u32[1] ^= ROTL(X0.m128i_u32[0] + X0.m128i_u32[3], 7);  X1.m128i_u32[2] ^= ROTL(X1.m128i_u32[1] + X1.m128i_u32[0], 7);
		X2.m128i_u32[3] ^= ROTL(X2.m128i_u32[2] + X2.m128i_u32[1], 7);  X3.m128i_u32[0] ^= ROTL(X3.m128i_u32[3] + X3.m128i_u32[2], 7);
		X0.m128i_u32[2] ^= ROTL(X0.m128i_u32[1] + X0.m128i_u32[0], 9);  X1.m128i_u32[3] ^= ROTL(X1.m128i_u32[2] + X1.m128i_u32[1], 9);
		X2.m128i_u32[0] ^= ROTL(X2.m128i_u32[3] + X2.m128i_u32[2], 9);  X3.m128i_u32[1] ^= ROTL(X3.m128i_u32[0] + X3.m128i_u32[3], 9);

		X0.m128i_u32[3] ^= ROTL(X0.m128i_u32[2] + X0.m128i_u32[1], 13);  X1.m128i_u32[0] ^= ROTL(X1.m128i_u32[3] + X1.m128i_u32[2], 13);
		X2.m128i_u32[1] ^= ROTL(X2.m128i_u32[0] + X2.m128i_u32[3], 13);  X3.m128i_u32[2] ^= ROTL(X3.m128i_u32[1] + X3.m128i_u32[0], 13);
		X0.m128i_u32[0] ^= ROTL(X0.m128i_u32[3] + X0.m128i_u32[2], 18);  X1.m128i_u32[1] ^= ROTL(X1.m128i_u32[0] + X1.m128i_u32[3], 18);
		X2.m128i_u32[2] ^= ROTL(X2.m128i_u32[1] + X2.m128i_u32[0], 18);  X3.m128i_u32[3] ^= ROTL(X3.m128i_u32[2] + X3.m128i_u32[1], 18);
	}

	B[0] = _mm_add_epi32(B[0], X0);
	B[1] = _mm_add_epi32(B[1], X1);
	B[2] = _mm_add_epi32(B[2], X2);
	B[3] = _mm_add_epi32(B[3], X3);
}

#else

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16], int i)
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;

	if (i <= 128) {
		// a xor 0 = a
		x00 = B[ 0] = Bx[ 0]; x01 = B[ 1] = Bx[ 1]; x02 = B[ 2] = Bx[ 2]; x03 = B[ 3] = Bx[ 3];
		x04 = B[ 4] = Bx[ 4]; x05 = B[ 5] = Bx[ 5]; x06 = B[ 6] = Bx[ 6]; x07 = B[ 7] = Bx[ 7];
		x08 = B[ 8] = Bx[ 8]; x09 = B[ 9] = Bx[ 9]; x10 = B[10] = Bx[10]; x11 = B[11] = Bx[11];
		x12 = B[12] = Bx[12]; x13 = B[13] = Bx[13]; x14 = B[14] = Bx[14]; x15 = B[15] = Bx[15];
	} else {
		x00 = (B[ 0] ^= Bx[ 0]);
		x01 = (B[ 1] ^= Bx[ 1]);
		x02 = (B[ 2] ^= Bx[ 2]);
		x03 = (B[ 3] ^= Bx[ 3]);
		x04 = (B[ 4] ^= Bx[ 4]);
		x05 = (B[ 5] ^= Bx[ 5]);
		x06 = (B[ 6] ^= Bx[ 6]);
		x07 = (B[ 7] ^= Bx[ 7]);
		x08 = (B[ 8] ^= Bx[ 8]);
		x09 = (B[ 9] ^= Bx[ 9]);
		x10 = (B[10] ^= Bx[10]);
		x11 = (B[11] ^= Bx[11]);
		x12 = (B[12] ^= Bx[12]);
		x13 = (B[13] ^= Bx[13]);
		x14 = (B[14] ^= Bx[14]);
		x15 = (B[15] ^= Bx[15]);
	}

	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

#endif

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
	do { \
		t0 = h + S1(e) + Ch(e, f, g) + k; \
		t1 = S0(a) + Maj(a, b, c); \
		d += t0; \
		h  = t0 + t1; \
		} while (0)

/* Adjusted round function for rotating state */
#define RNDr(S, W, i) \
	RND(S[(64 - i) % 8], S[(65 - i) % 8], \
	    S[(66 - i) % 8], S[(67 - i) % 8], \
	    S[(68 - i) % 8], S[(69 - i) % 8], \
	    S[(70 - i) % 8], S[(71 - i) % 8], \
	    W[i] + sha256_k[i])


static void sha256_transform_volatile(uint32_t *state, uint32_t *block)
{
	uint32_t* W=block; //note: block needs to be a mutable 64 int32_t
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	for (i = 16; i < 64; i += 2) {
		W[i]   = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W, 0);
	RNDr(S, W, 1);
	RNDr(S, W, 2);
	RNDr(S, W, 3);
	RNDr(S, W, 4);
	RNDr(S, W, 5);
	RNDr(S, W, 6);
	RNDr(S, W, 7);
	RNDr(S, W, 8);
	RNDr(S, W, 9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

// standard sha256 hash
#if 1
static void sha256_hash(unsigned char *hash, const unsigned char *data, int len)
{
	uint32_t _ALIGN(64) S[16];
	uint32_t _ALIGN(64) T[64];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64) {
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char *)T)[r] = 0x80;
		for (i = 0; i < 16; i++)
			T[i] = be32dec(T + i);
		if (r < 56)
			T[15] = 8 * len;
		//sha256_transform(S, T, 0);
		sha256_transform_volatile(S, T);
	}
	for (i = 0; i < 8; i++)
		be32enc((uint32_t *)hash + i, S[i]);
}
#else
#include <openssl/sha.h>
static void sha256_hash(unsigned char *hash, const unsigned char *data, int len)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(hash, &ctx);
}
#endif

// hash exactly 64 bytes (ie, sha256 block size)
static void sha256_hash512(uint32_t *hash, const uint32_t *data)
{
	uint32_t _ALIGN(64) S[16];
	uint32_t _ALIGN(64) T[64];
	uchar _ALIGN(64) E[64*4] = { 0 };
	int i;

	sha256_init(S);

	for (i = 0; i < 16; i++)
		T[i] = be32dec(&data[i]);
	sha256_transform_volatile(S, T);

	E[3]  = 0x80;
	E[61] = 0x02; // T[15] = 8 * 64 => 0x200;
	sha256_transform_volatile(S, (uint32_t*)E);

	for (i = 0; i < 8; i++)
		be32enc(&hash[i], S[i]);
}

void pluck_hash(uint32_t *hash, const uint32_t *data, uchar *hashbuffer, const int N)
{
	int size = N * 1024;
	sha256_hash(hashbuffer, (void*)data, BLOCK_HEADER_SIZE);
	memset(&hashbuffer[32], 0, 32);

	for(int i = 64; i < size - 32; i += 32)
	{
		uint32_t _ALIGN(64) randseed[16];
		uint32_t _ALIGN(64) randbuffer[16];
		uint32_t _ALIGN(64) joint[16];
		//i-4 because we use integers for all references against this, and we don't want to go 3 bytes over the defined area
		//we could use size here, but then it's probable to use 0 as the value in most cases
		int randmax = i - 4;

		//setup randbuffer to be an array of random indexes
		memcpy(randseed, &hashbuffer[i - 64], 64);

		if(i > 128) memcpy(randbuffer, &hashbuffer[i - 128], 64);
		//else memset(randbuffer, 0, 64);

		xor_salsa8((void*)randbuffer, (void*)randseed, i);
		memcpy(joint, &hashbuffer[i - 32], 32);

		//use the last hash value as the seed
		for (int j = 32; j < 64; j += 4)
		{
			//every other time, change to next random index
			//randmax - 32 as otherwise we go beyond memory that's already been written to
			uint32_t rand = randbuffer[(j - 32) >> 2] % (randmax - 32);
			joint[j >> 2] = *((uint32_t *)&hashbuffer[rand]);
		}

		sha256_hash512((uint32_t*) &hashbuffer[i], joint);

		//setup randbuffer to be an array of random indexes
		//use last hash value and previous hash value(post-mixing)
		memcpy(randseed, &hashbuffer[i - 32], 64);

		if(i > 128) memcpy(randbuffer, &hashbuffer[i - 128], 64);
		//else memset(randbuffer, 0, 64);

		xor_salsa8((void*)randbuffer, (void*)randseed, i);

		//use the last hash value as the seed
		for (int j = 0; j < 32; j += 2)
		{
			uint32_t rand = randbuffer[j >> 1] % randmax;
			*((uint32_t *)(hashbuffer + rand)) = *((uint32_t *)(hashbuffer + j + randmax));
		}
	}

	memcpy(hash, hashbuffer, 32);
}

int scanhash_pluck(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
	unsigned char *scratchbuf, int N)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	uint32_t n = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0xffff;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {
		//be32enc(&endiandata[19], n);
		endiandata[19] = n;
		pluck_hash(hash, endiandata, scratchbuf, N);

		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			work_set_target_ratio(work, hash);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = htobe32(endiandata[19]);
			return 1;
		}
		n++;
	} while (n < max_nonce && !(*restart));

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
