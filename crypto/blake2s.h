/**
 * BLAKE2 reference source code package - reference C implementations
 *
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#pragma once
#ifndef __BLAKE2_H__
#define __BLAKE2_H__

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <inttypes.h>
#define inline __inline
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

/* blake2-impl.h */

static inline uint32_t load32(const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	return *(uint32_t *)(src);
#else
	const uint8_t *p = (uint8_t *)src;
	uint32_t w = *p++;
	w |= (uint32_t)(*p++) << 8;
	w |= (uint32_t)(*p++) << 16;
	w |= (uint32_t)(*p++) << 24;
	return w;
#endif
}

static inline void store32(void *dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	*(uint32_t *)(dst) = w;
#else
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

static inline uint64_t load48(const void *src)
{
	const uint8_t *p = (const uint8_t *)src;
	uint64_t w = *p++;
	w |= (uint64_t)(*p++) << 8;
	w |= (uint64_t)(*p++) << 16;
	w |= (uint64_t)(*p++) << 24;
	w |= (uint64_t)(*p++) << 32;
	w |= (uint64_t)(*p++) << 40;
	return w;
}

static inline void store48(void *dst, uint64_t w)
{
	uint8_t *p = (uint8_t *)dst;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w; w >>= 8;
	*p++ = (uint8_t)w;
}

/* prevents compiler optimizing out memset() */
static inline void secure_zero_memory(void *v, size_t n)
{
	volatile uint8_t *p = ( volatile uint8_t * )v;

	while( n-- ) *p++ = 0;
}

/* blake2.h */

enum blake2s_constant
{
	BLAKE2S_BLOCKBYTES = 64,
	BLAKE2S_OUTBYTES   = 32,
	BLAKE2S_KEYBYTES   = 32,
	BLAKE2S_SALTBYTES  = 8,
	BLAKE2S_PERSONALBYTES = 8
};

#pragma pack(push, 1)
typedef struct __blake2s_param
{
	uint8_t  digest_length; // 1
	uint8_t  key_length;    // 2
	uint8_t  fanout;        // 3
	uint8_t  depth;         // 4
	uint32_t leaf_length;   // 8
	uint8_t  node_offset[6];// 14
	uint8_t  node_depth;    // 15
	uint8_t  inner_length;  // 16
	// uint8_t  reserved[0];
	uint8_t  salt[BLAKE2S_SALTBYTES]; // 24
	uint8_t  personal[BLAKE2S_PERSONALBYTES];  // 32
} blake2s_param;

ALIGN( 64 ) typedef struct __blake2s_state
{
	uint32_t h[8];
	uint32_t t[2];
	uint32_t f[2];
	uint8_t  buf[2 * BLAKE2S_BLOCKBYTES];
	size_t   buflen;
	uint8_t  last_node;
} blake2s_state;
#pragma pack(pop)

#if defined(__cplusplus)
extern "C" {
#endif

	int blake2s_compress( blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES] );

	// Streaming API
	int blake2s_init( blake2s_state *S, const uint8_t outlen );
	int blake2s_init_key( blake2s_state *S, const uint8_t outlen, const void *key, const uint8_t keylen );
	int blake2s_init_param( blake2s_state *S, const blake2s_param *P );
	int blake2s_update( blake2s_state *S, const uint8_t *in, uint64_t inlen );
	int blake2s_final( blake2s_state *S, uint8_t *out, uint8_t outlen );

	// Simple API
	int blake2s( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen );

	// Direct Hash Mining Helpers
	#define blake2s_salt32(out, in, inlen, key32) blake2s(out, in, key32, 32, inlen, 32) /* neoscrypt */
	#define blake2s_simple(out, in, inlen) blake2s(out, in, NULL, 32, inlen, 0)

#if defined(__cplusplus)
}
#endif

#endif
