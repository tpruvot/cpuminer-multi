// RainForest hash algorithm
// Author: Bill Schneider
// Created: Feb 13th, 2018
// Updated: Apr 21th, 2019
//
// RainForest uses native integer operations which are extremely fast on
// modern 64-bit processors, significantly slower on 32-bit processors such
// as GPUs, and extremely slow if at all implementable on FPGAs and ASICs.
// It makes an intensive use of the L1 cache to maintain a heavy intermediary
// state favoring modern CPUs compared to GPUs (small L1 cache shared by many
// shaders) or FPGAs (very hard to implement the required low-latency cache)
// when scanning ranges for nonces. Finally, it uses 96 MB of work
// area per thread in order to incur a cost to highly parallel processors such
// as high-end GPUs. The purpose is to create a fair balance between all mining
// equipments, from mobile phones to extreme performance GPUs and to rule out
// farming factories relying on ASICs, FPGAs, or any other very expensive
// solution. The CRC32 instruction is used a lot as it is extremely fast on
// low-power ARM chips and allows such devices to rival high-end PCs mining
// performance. Note that CRC32 is not used for security at all, only to
// disturb data.
//
// Build instructions on Ubuntu 16.04 to 18.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.
//
// Note: always use the same options to build all files!
//

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "rfv2.h"

// these archs are fine with unaligned reads
#if defined(__x86_64__)||defined(__aarch64__)
#define RF_UNALIGNED_LE64
#define RF_UNALIGNED_LE32
#elif defined(__i386__)||defined(__ARM_ARCH_7A__)
#define RF_UNALIGNED_LE32
#endif

#define RFV2_INIT_CRC 20180213

#ifndef RF_ALIGN
#ifdef _MSC_VER
#define RF_ALIGN(x) __declspec(align(x))
#else
#define RF_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

// for aes2r_encrypt()
#include "rf_aes2r.c"

// for rf_crc32_32()
#include "rf_crc32.c"

// this seems necessary only for gcc, otherwise hash is bogus
#ifdef _MSC_VER
typedef uint8_t  rf_u8;
typedef uint16_t rf_u16;
typedef uint32_t rf_u32;
typedef uint64_t rf_u64;
#else
typedef __attribute__((may_alias)) uint8_t  rf_u8;
typedef __attribute__((may_alias)) uint16_t rf_u16;
typedef __attribute__((may_alias)) uint32_t rf_u32;
typedef __attribute__((may_alias)) uint64_t rf_u64;
#endif

#define RFV2_RAMBOX_HIST 1536

typedef union {
	rf_u8  b[32];
	rf_u16 w[16];
	rf_u32 d[8];
	rf_u64 q[4];
} rf_hash256_t;

typedef struct RF_ALIGN(16) rfv2_ctx {
	uint32_t word;  // LE pending message
	uint32_t len;   // total message length
	uint32_t crc;
	uint16_t changes; // must remain lower than RFV2_RAMBOX_HIST, 65535=R/O
	uint16_t left_bits; // adjust rambox probability
	uint64_t *rambox;
	uint32_t rb_o;    // rambox offset
	uint32_t rb_l;    // rambox length
	rf_hash256_t RF_ALIGN(32) hash;
	uint32_t hist[RFV2_RAMBOX_HIST];
	uint64_t prev[RFV2_RAMBOX_HIST];
} rfv2_ctx_t;

// the table is used as an 8 bit-aligned array of uint64_t for the first word,
// and as a 16 bit-aligned array of uint64_t for the second word. It is filled
// with the sha256 of "RainForestProCpuAntiAsic", iterated over and over until
// the table is filled. The highest offset being ((uint16_t *)table)[255] we
// need to add 6 extra bytes at the end to read an uint64_t. Maybe calculated
// on a UNIX system with this loop :
//
//   ref="RainForestProCpuAntiAsic"
//   for ((i=0;i<18;i++)); do
//     set $(echo -n $ref|sha256sum)
//     echo $1|sed 's/\(..\)/0x\1,/g'
//     ref=$(printf $(echo $1|sed 's/\(..\)/\\x\1/g'))
//   done

static const uint8_t rfv2_table[256 * 2 + 6] = {
	0x8e,0xc1,0xa8,0x04,0x38,0x78,0x7c,0x54,0x29,0x23,0x1b,0x78,0x9f,0xf9,0x27,0x54,
	0x11,0x78,0x95,0xb6,0xaf,0x78,0x45,0x16,0x2b,0x9e,0x91,0xe8,0x97,0x25,0xf8,0x63,
	0x82,0x56,0xcf,0x48,0x6f,0x82,0x14,0x0d,0x61,0xbe,0x47,0xd1,0x37,0xee,0x30,0xa9,
	0x28,0x1e,0x4b,0xbf,0x07,0xcd,0x41,0xdf,0x23,0x21,0x12,0xb8,0x81,0x99,0x1d,0xe6,
	0x68,0xcf,0xfa,0x2d,0x8e,0xb9,0x88,0xa7,0x15,0xce,0x9e,0x2f,0xeb,0x1b,0x0f,0x67,
	0x20,0x68,0x6c,0xa9,0x5d,0xc1,0x7c,0x76,0xdf,0xbd,0x98,0x61,0xb4,0x14,0x65,0x40,
	0x1e,0x72,0x51,0x74,0x93,0xd3,0xad,0xbe,0x46,0x0a,0x25,0xfb,0x6a,0x5e,0x1e,0x8a,
	0x5a,0x03,0x3c,0xab,0x12,0xc2,0xd4,0x07,0x91,0xab,0xc9,0xdf,0x92,0x2c,0x85,0x6a,
	0xa6,0x25,0x1e,0x66,0x50,0x26,0x4e,0xa8,0xbd,0xda,0x88,0x1b,0x95,0xd4,0x00,0xeb,
	0x0d,0x1c,0x9b,0x3c,0x86,0xc7,0xb2,0xdf,0xb4,0x5a,0x36,0x15,0x8e,0x04,0xd2,0x54,
	0x79,0xd2,0x3e,0x3d,0x99,0x50,0xa6,0x12,0x4c,0x32,0xc8,0x51,0x14,0x4d,0x4b,0x0e,
	0xbb,0x17,0x80,0x8f,0xa4,0xc4,0x99,0x72,0xd7,0x14,0x4b,0xef,0xed,0x14,0xe9,0x17,
	0xfa,0x9b,0x5d,0x37,0xd6,0x2f,0xef,0x02,0xd6,0x71,0x0a,0xbd,0xc5,0x40,0x11,0x90,
	0x90,0x4e,0xb4,0x4c,0x72,0x51,0x7a,0xd8,0xba,0x30,0x4d,0x8c,0xe2,0x11,0xbb,0x6d,
	0x4b,0xbc,0x6f,0x14,0x0c,0x9f,0xfa,0x5e,0x66,0x40,0x45,0xcb,0x7d,0x1b,0x3a,0xc5,
	0x5e,0x9c,0x1e,0xcc,0xbd,0x16,0x3b,0xcf,0xfb,0x2a,0xd2,0x08,0x2a,0xf8,0x3d,0x46,
	0x93,0x90,0xb3,0x66,0x81,0x34,0x7f,0x6d,0x9b,0x8c,0x99,0x03,0xc5,0x27,0xa3,0xd9,
	0xce,0x90,0x88,0x0f,0x55,0xc3,0xa1,0x60,0x53,0xc8,0x0d,0x25,0xae,0x61,0xd9,0x72,
	0x48,0x1d,0x6c,0x61,0xd2,0x87,0xdd,0x3d,0x23,0xf5,0xde,0x93,0x39,0x4c,0x43,0x9a,
	0xf9,0x37,0xf2,0x61,0xd7,0xf8,0xea,0x65,0xf0,0xf1,0xde,0x3f,0x05,0x57,0x83,0x81,
	0xde,0x02,0x62,0x49,0xd4,0x32,0x7e,0x4a,0xd4,0x9f,0x40,0x7e,0xb9,0x91,0xb1,0x35,
	0xf7,0x62,0x3f,0x65,0x9e,0x4d,0x2b,0x10,0xde,0xd4,0x77,0x64,0x0f,0x84,0xad,0x92,
	0xe7,0xa3,0x8a,0x10,0xc1,0x14,0xeb,0x57,0xc4,0xad,0x8e,0xc2,0xc7,0x32,0xa3,0x7e,
	0x50,0x1f,0x7c,0xbb,0x2e,0x5f,0xf5,0x18,0x22,0xea,0xec,0x9d,0xa4,0x77,0xcd,0x85,
	0x04,0x2f,0x20,0x61,0x72,0xa7,0x0c,0x92,0x06,0x4d,0x01,0x70,0x9b,0x35,0xa1,0x27,
	0x32,0x6e,0xb9,0x78,0xe0,0xaa,0x5f,0x91,0xa6,0x51,0xe3,0x63,0xf8,0x97,0x2f,0x60,
	0xd9,0xfb,0x15,0xe5,0x59,0xcf,0x31,0x3c,0x61,0xc7,0xb5,0x61,0x2a,0x6b,0xdd,0xd1,
	0x09,0x70,0xc0,0xcf,0x94,0x7a,0xcc,0x31,0x94,0xb1,0xa2,0xf6,0x95,0xc0,0x38,0x3d,
	0xef,0x19,0x30,0x70,0xdd,0x62,0x32,0x8f,0x7c,0x30,0xb9,0x18,0xf8,0xe7,0x8f,0x0a,
	0xaa,0xb6,0x00,0x86,0xf2,0xe0,0x30,0x5f,0xa2,0xe8,0x00,0x8e,0x05,0xa0,0x22,0x18,
	0x9f,0x83,0xd4,0x3a,0x85,0x10,0xb9,0x51,0x8d,0x07,0xf0,0xb3,0xcd,0x9b,0x55,0xa1,
	0x14,0xce,0x0f,0xb2,0xcf,0xb8,0xce,0x2d,0xe6,0xe8,0x35,0x32,0x1f,0x22,0xb5,0xec,
	0xd0,0xb9,0x72,0xa8,0xb4,0x97
	//,0x6e,0x0a,0x47,0xcd,0x5a,0xf0,0xdc,0xeb,0xfd,0x46,
	//0xe5,0x6e,0x83,0xe6,0x1a,0xcc,0x4a,0x8b,0xa5,0x28,0x9e,0x50,0x48,0xa9,0xa2,0x6b,
};

// this is made of the last iteration of the rfv2_table (18th transformation)
static const uint8_t rfv2_iv[32] = {
	0x78,0xe9,0x90,0xd3,0xb3,0xc8,0x9b,0x7b,0x0a,0xc4,0x86,0x6e,0x4e,0x38,0xb3,0x6b,
	0x33,0x68,0x7c,0xed,0x73,0x35,0x4b,0x0a,0x97,0x25,0x4c,0x77,0x7a,0xaa,0x61,0x1b
};

/* le32 memory to host representation */
static inline uint32_t rf_le32toh(uint8_t *x)
{
	return x[0] + (x[1] << 8) + (x[2] << 16) + (x[3] << 24);
}

// mix the current state with the crc and return the new crc
static inline uint32_t rf_crc32x4(rf_u32 *state, uint32_t crc)
{
	crc = state[0] = rf_crc32_32(crc, state[0]);
	crc = state[1] = rf_crc32_32(crc, state[1]);
	crc = state[2] = rf_crc32_32(crc, state[2]);
	crc = state[3] = rf_crc32_32(crc, state[3]);
	return crc;
}

// add to _msg_ its own crc32. use -mcpu=cortex-a53+crc to enable native CRC
// instruction on ARM.
static inline uint64_t rf_add64_crc32(uint64_t msg)
{
	return msg + rf_crc32_64(0, msg);
}

// read 64 bit from possibly unaligned memory address _p_ in little endian mode
static inline uint64_t rf_memr64(const uint8_t *p)
{
#ifdef RF_UNALIGNED_LE64
	return *(uint64_t *)p;
#else
	uint64_t ret;
	int byte;
	for (ret = byte = 0; byte < 8; byte++)
		ret += (uint64_t)p[byte] << (byte * 8);
	return ret;
#endif
}

// return rainforest lower word entry for index
static inline uint64_t rf_wltable(uint8_t index)
{
	return rf_memr64(&rfv2_table[index]);
}

// return rainforest upper word entry for _index_
static inline uint64_t rf_whtable(uint8_t index)
{
	return rf_memr64(&rfv2_table[index * 2]);
}

// rotate left vector _v_ by _bits_ bits
static inline uint64_t rf_rotl64(uint64_t v, uint64_t bits)
{
#if !defined(RF_NOASM) && defined(__x86_64__)
	__asm__("rol %1, %0" : "+r"(v) : "c"((uint8_t)bits));
#else
#if !defined(__ARM_ARCH_8A) && !defined(__x86_64__)
	bits &= 63;
#endif
	v = (v << bits) | (v >> (-bits & 63));
#endif
	return v;
}

// rotate right vector _v_ by _bits_ bits
static inline uint64_t rf_rotr64(uint64_t v, uint64_t bits)
{
#if !defined(RF_NOASM) && defined(__x86_64__)
	__asm__("ror %1, %0" : "+r"(v) : "c"((uint8_t)bits));
#else
#if !defined(__ARM_ARCH_8A) && !defined(__x86_64__)
	bits &= 63;
#endif
	v = (v >> bits) | (v << (-bits & 63));
#endif
	return v;
}

// reverse all bytes in the word _v_
static inline uint64_t rf_bswap64(uint64_t v)
{
#if !defined(RF_NOASM) && defined(__x86_64__) && !defined(_MSC_VER)
	__asm__("bswapq %0":"+r"(v));
#elif !defined(RF_NOASM) && defined(__aarch64__)
	__asm__("rev %0,%0\n":"+r"(v));
#else
	v = ((v & 0xff00ff00ff00ff00ULL) >> 8)  | ((v & 0x00ff00ff00ff00ffULL) << 8);
	v = ((v & 0xffff0000ffff0000ULL) >> 16) | ((v & 0x0000ffff0000ffffULL) << 16);
	v = (v >> 32) | (v << 32);
#endif
	return v;
}

// reverse all bits in the word _v_
static inline uint64_t rf_revbit64(uint64_t v)
{
#if !defined(RF_NOASM) && defined(__aarch64__)
	__asm__ volatile("rbit %0, %1\n" : "=r"(v) : "r"(v));
#else
	v = ((v & 0xaaaaaaaaaaaaaaaaULL) >> 1) | ((v & 0x5555555555555555ULL) << 1);
	v = ((v & 0xccccccccccccccccULL) >> 2) | ((v & 0x3333333333333333ULL) << 2);
	v = ((v & 0xf0f0f0f0f0f0f0f0ULL) >> 4) | ((v & 0x0f0f0f0f0f0f0f0fULL) << 4);
#if !defined(RF_NOASM) && defined(__x86_64__)
	__asm__("bswapq %0" : "=r"(v) : "0"(v));
#else
	v = ((v & 0xff00ff00ff00ff00ULL) >> 8)  | ((v & 0x00ff00ff00ff00ffULL) << 8);
	v = ((v & 0xffff0000ffff0000ULL) >> 16) | ((v & 0x0000ffff0000ffffULL) << 16);
	v = (v >> 32) | (v << 32);
#endif
#endif
	return v;
}

#if !defined(__GNUC__) || (__GNUC__ < 4 || __GNUC__ == 4 && __GNUC_MINOR__ < 7)
#if !defined(__GNUC__) // also covers clang
int __builtin_clzll(uint64_t x)
{
	uint64_t y;
	int n = 64;

	y = x >> 32; if (y) { x = y; n -= 32; }
	y = x >> 16; if (y) { x = y; n -= 16; }
	y = x >>  8; if (y) { x = y; n -=  8; }
	y = x >>  4; if (y) { x = y; n -=  4; }
	y = x >>  2; if (y) { x = y; n -=  2; }
	y = x >>  1; if (y) { x = y; n -=  1; }
	return n - x;
}

#endif
static inline int __builtin_clrsbll(int64_t x)
{
	if (x < 0)
		return __builtin_clzll(~(x << 1));
	else
		return __builtin_clzll(x << 1);
}
#endif

// write (_x_,_y_) at cell _cell_ for offset _ofs_
static inline void rf_w128(uint64_t *cell, size_t ofs, uint64_t x, uint64_t y)
{
#if !defined(RF_NOASM) && (defined(__ARM_ARCH_8A) || defined(__AARCH64EL__))
	// 128 bit at once is faster when exactly two parallelizable instructions are
	// used between two calls to keep the pipe full.
	__asm__ volatile("stp %0, %1, [%2,%3]\n\t"
			 : /* no output */
			 : "r"(x), "r"(y), "r" (cell), "I" (ofs * 8));
#else
	cell[ofs + 0] = x;
	cell[ofs + 1] = y;
#endif
}

// lookup _old_ in _rambox_, update it and perform a substitution if a matching
// value is found.
static inline uint64_t rfv2_rambox(rfv2_ctx_t *ctx, uint64_t old)
{
	uint64_t *p, k;
	uint32_t idx;

	k = old;
	old = rf_add64_crc32(old);
	old ^= rf_revbit64(k);
	if (__builtin_clrsbll(old) >= ctx->left_bits) {
		idx = ctx->rb_o + old % ctx->rb_l;
		p = &ctx->rambox[idx];
		k = *p;
		old += rf_rotr64(k, (uint8_t)(old / ctx->rb_l));
		if (ctx->changes != 65535) {
			*p = old;
			if (ctx->changes < RFV2_RAMBOX_HIST) {
				ctx->hist[ctx->changes] = idx;
				ctx->prev[ctx->changes] = k;
				ctx->changes++;
			}
		}
	}
	return old;
}

// initialize the ram box
void rfv2_raminit(void *area)
{
	uint64_t pat1 = 0x0123456789ABCDEFULL;
	uint64_t pat2 = 0xFEDCBA9876543210ULL;
	uint64_t pat3;
	uint32_t pos;
	uint64_t *rambox = (uint64_t *)area;

	// Note: no need to mask the higher bits on armv8 nor x86 :
	//
	// From ARMv8's ref manual :
	//     The register that is specified for a shift can be 32-bit or
	//     64-bit. The amount to be shifted can be specified either as
	//     an immediate, that is up to register size minus one, or by
	//     a register where the value is taken only from the bottom five
	//     (modulo-32) or six (modulo-64) bits.
	//
	// Here we rotate pat2 by pat1's bits and put it into pat1, and in
	// parallel we rotate pat1 by pat2's bits and put it into pat2. Thus
	// the two data blocks are exchanged in addition to being rotated.
	// What is stored each time is the previous and the rotated blocks,
	// which only requires one rotate and a register rename.

	for (pos = 0; pos < RFV2_RAMBOX_SIZE; pos += 16) {
		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x111;
		rf_w128(rambox + pos, 0, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x222;
		rf_w128(rambox + pos, 2, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x333;
		rf_w128(rambox + pos, 4, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x444;
		rf_w128(rambox + pos, 6, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x555;
		rf_w128(rambox + pos, 8, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x666;
		rf_w128(rambox + pos, 10, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x777;
		rf_w128(rambox + pos, 12, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x888;
		rf_w128(rambox + pos, 14, pat2, pat3);
	}
}

#ifdef RF_DEBUG_RAMBOX
// verify the ram box
static void rfv2_ram_test(const void *area)
{
	uint64_t pat1 = 0x0123456789ABCDEFULL;
	uint64_t pat2 = 0xFEDCBA9876543210ULL;
	uint64_t pat3;
	uint32_t pos;
	const uint64_t *rambox = (const uint64_t *)area;

	// Note: no need to mask the higher bits on armv8 nor x86 :
	//
	// From ARMv8's ref manual :
	//     The register that is specified for a shift can be 32-bit or
	//     64-bit. The amount to be shifted can be specified either as
	//     an immediate, that is up to register size minus one, or by
	//     a register where the value is taken only from the bottom five
	//     (modulo-32) or six (modulo-64) bits.
	//
	// Here we rotate pat2 by pat1's bits and put it into pat1, and in
	// parallel we rotate pat1 by pat2's bits and put it into pat2. Thus
	// the two data blocks are exchanged in addition to being rotated.
	// What is stored each time is the previous and the rotated blocks,
	// which only requires one rotate and a register rename.

	for (pos = 0; pos < RFV2_RAMBOX_SIZE; pos += 16) {
		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x111;
		if (rambox[pos + 0] != pat1)
			abort();

		if (rambox[pos + 1] != pat3)
			abort();

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x222;
		if (rambox[pos + 2] != pat2)
			abort();

		if (rambox[pos + 3] != pat3)
			abort();

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x333;
		if (rambox[pos + 4] != pat1)
			abort();

		if (rambox[pos + 5] != pat3)
			abort();

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x444;
		if (rambox[pos + 6] != pat2)
			abort();

		if (rambox[pos + 7] != pat3)
			abort();

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x555;
		if (rambox[pos + 8] != pat1)
			abort();

		if (rambox[pos + 9] != pat3)
			abort();

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x666;
		if (rambox[pos + 10] != pat2)
			abort();

		if (rambox[pos + 11] != pat3)
			abort();

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x777;
		if (rambox[pos + 12] != pat1)
			abort();

		if (rambox[pos + 13] != pat3)
			abort();

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x888;
		if (rambox[pos + 14] != pat2)
			abort();

		if (rambox[pos + 15] != pat3)
			abort();
	}
}
#endif

// return p/q into p and rev(rev(q)+p) into q
static inline void rfv2_div_mod(uint64_t *p, uint64_t *q)
{
	uint64_t x = *p;
	*p = x / *q;
#if !defined(RF_NOASM) && !defined(_MSC_VER)
	__asm__ volatile("" :: "r"(*p)); // force to place the div first
#endif
	*q = rf_revbit64(rf_revbit64(*q)+x);
}

// exec the div/mod box. _v0_ and _v1_ must be aligned.
static inline void rfv2_divbox(rf_u64 *v0, rf_u64 *v1)
{
	uint64_t pl, ql, ph, qh;

	//---- low word ----    ---- high word ----
	pl = ~*v0;              ph = ~*v1;
	ql = rf_bswap64(*v0);   qh = rf_bswap64(*v1);

	if (!pl || !ql)   { pl = ql = 0; }
	else if (pl > ql) rfv2_div_mod(&pl, &ql);
	else              rfv2_div_mod(&ql, &pl);

	if (!ph || !qh)   { ph = qh = 0; }
	else if (ph > qh) rfv2_div_mod(&ph, &qh);
	else              rfv2_div_mod(&qh, &ph);

	pl += qh;               ph += ql;
	*v0 -= pl;              *v1 -= ph;
}

// exec the rotation/add box. _v0_ and _v1_ must be aligned.
static inline void rfv2_rotbox(rf_u64 *v0, rf_u64 *v1, uint8_t b0, uint8_t b1)
{
	uint64_t l, h;

	//---- low word ----       ---- high word ----
	l   = *v0;                 h   = *v1;
	l   = rf_rotr64(l, b0);    h   = rf_rotl64(h, b1);
	l  += rf_wltable(b0);      h  += rf_whtable(b1);
	b0  = (uint8_t)l;          b1  = (uint8_t)h;
	l   = rf_rotl64(l, b1);    h   = rf_rotr64(h, b0);
	b0  = (uint8_t)l;          b1  = (uint8_t)h;
	l   = rf_rotr64(l, b1);    h   = rf_rotl64(h, b0);
	*v0 = l;                   *v1 = h;
}

// mix the current state with the current crc
static inline uint32_t rfv2_scramble(rfv2_ctx_t *ctx)
{
	return ctx->crc = rf_crc32x4(ctx->hash.d, ctx->crc);
}

// mix the state with the crc and the pending text, and update the crc
static inline void rfv2_inject(rfv2_ctx_t *ctx)
{
	ctx->crc =
		(ctx->len & 3) == 0 ? rf_crc32_32(rfv2_scramble(ctx), ctx->word):
		(ctx->len & 3) == 3 ? rf_crc32_24(rfv2_scramble(ctx), ctx->word):
		(ctx->len & 3) == 2 ? rf_crc32_16(rfv2_scramble(ctx), ctx->word):
		rf_crc32_8(rfv2_scramble(ctx), ctx->word);
	ctx->word = 0;
}

// rotate the hash by 32 bits. Not using streaming instructions (SSE/NEON) is
// faster because the compiler can follow moves an use register renames.
static inline void rfv2_rot32x256(rf_hash256_t *hash)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__ARM_ARCH_7A__)
	uint32_t t0, t1, t2;

	t0 = hash->d[0];
	t1 = hash->d[1];
	t2 = hash->d[2];
	hash->d[1] = t0;
	hash->d[2] = t1;

	t0 = hash->d[3];
	t1 = hash->d[4];
	hash->d[3] = t2;
	hash->d[4] = t0;

	t2 = hash->d[5];
	t0 = hash->d[6];
	hash->d[5] = t1;
	hash->d[6] = t2;

	t1 = hash->d[7];
	hash->d[7] = t0;
	hash->d[0] = t1;
#else
	uint32_t tmp = hash->d[7];

	memmove(&hash->d[1], &hash->d[0], 28);
	hash->d[0] = tmp;
#endif
}

// encrypt the first 128 bits of the hash using the last 128 bits as the key
static inline void rfv2_aesenc(rfv2_ctx_t *ctx)
{
	aes2r_encrypt((uint8_t *)ctx->hash.b, (uint8_t *)ctx->hash.b + 16);
}

// each new round consumes exactly 32 bits of text at once and perturbates
// 128 bits of output, 96 of which overlap with the previous round, and 32
// of which are new. With 5 rounds or more each output bit depends on every
// input bit.
static inline void rfv2_one_round(rfv2_ctx_t *ctx)
{
	uint64_t carry;

	rfv2_rot32x256(&ctx->hash);

	carry = ((uint64_t)ctx->len << 32) + ctx->crc;
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry), (uint8_t)(carry >> 56));
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 8), (uint8_t)(carry >> 48));
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 16), (uint8_t)(carry >> 40));
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 24), (uint8_t)(carry >> 32));
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_inject(ctx);
	rfv2_aesenc(ctx);
	rfv2_scramble(ctx);
}

// initialize the hash state
static void rfv2_init(rfv2_ctx_t *ctx, uint32_t seed, void *rambox)
{
	memcpy(ctx->hash.b, rfv2_iv, sizeof(ctx->hash.b));
	ctx->crc = seed;
	ctx->word = ctx->len = 0;
	ctx->changes = 0;
	ctx->rb_o = 0;
	ctx->rb_l = RFV2_RAMBOX_SIZE;
	ctx->rambox = (uint64_t *)rambox;
}

// update the hash context _ctx_ with _len_ bytes from message _msg_
static inline void rfv2_update(rfv2_ctx_t *ctx, const void *msg, size_t len)
{
	const uint8_t *msg8 = (uint8_t *)msg;

	while (len > 0) {
#ifdef RF_UNALIGNED_LE32
		if (!(ctx->len & 3) && len >= 4) {
			ctx->word = *(uint32_t *)msg8;
			ctx->len += 4;
			rfv2_one_round(ctx);
			msg8 += 4;
			len  -= 4;
			continue;
		}
#endif
		ctx->word |= ((uint32_t)*msg8++) << (8 * (ctx->len++ & 3));
		len--;
		if (!(ctx->len & 3))
			rfv2_one_round(ctx);
	}
}

// pad to the next 128-bit (16 bytes) boundary
static inline void rfv2_pad128(rfv2_ctx_t *ctx)
{
	const uint8_t pad128[16] = { 0, };
	uint32_t pad;

	pad = (16 - ctx->len) & 0xF;
	if (pad)
		rfv2_update(ctx, pad128, pad);
}

// finalize the hash and copy the result into _out_ if not null (256 bits)
static inline void rfv2_final(void *out, rfv2_ctx_t *ctx)
{
	// always run 5 extra rounds to complete the last 128 bits.
	// the 5th one is because the last processed block is only in
	// the ctx and was not mixed yet.
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);

	if (out)
		memcpy(out, ctx->hash.b, 32);
}

// compute an integer-based rough approximation of 1+256*(abs(sin(x/16)^3)+1)
// which does not depend on a floating point implementation. The period of the
// input is 2^32.
static unsigned int sin_scaled(unsigned int x)
{
	int i;

	i = ((x * 42722829) >> 24) - 128;
	x = 15 * i * i * abs(i);  // 0 to 15<<21
	x = (x + (x >> 4)) >> 17;
	return 257 - x;
}

// hash _len_ bytes from _in_ into _out_, using _seed_
// _rambox_ must be either NULL or a pointer to an area RFV2_RAMBOX_SIZE*8 bytes
// long preinitialized with rfv2_rambox_init(). If _rambox_ is NULL but _rambox_template_
// is set, it will be initialized from this rambox_template using memcpy().
// The function returns 0 on success or -1 on allocation failure if rambox is
// NULL.
int rfv2_hash2(void *out, const void *in, size_t len, void *rambox, const void *rambox_template, uint32_t seed)
{
	rfv2_ctx_t ctx;
	unsigned int loop, loops;
	int alloc_rambox = (rambox == NULL);
	uint32_t msgh;

	if (alloc_rambox) {
		rambox = malloc(RFV2_RAMBOX_SIZE * 8);
		if (rambox == NULL)
			return -1;

		if (rambox_template)
			memcpy(rambox, rambox_template, RFV2_RAMBOX_SIZE * 8);
		else
			rfv2_raminit(rambox);
	}

	//rfv2_ram_test(rambox);

	rfv2_init(&ctx, seed, rambox);
	msgh = rf_crc32_mem(0, in, len);
	ctx.rb_o = msgh % (ctx.rb_l / 2);
	ctx.rb_l = (ctx.rb_l / 2 - ctx.rb_o) * 2;

	loops = sin_scaled(msgh);
	if (loops >= 128)
		ctx.left_bits = 4;
	else if (loops >= 64)
		ctx.left_bits = 3;
	else if (loops >= 32)
		ctx.left_bits = 2;
	else if (loops >= 16)
		ctx.left_bits = 1;
	else
		ctx.left_bits = 0;
	for (loop = 0; loop < loops; loop++) {
		rfv2_update(&ctx, in, len);
		// pad to the next 256 bit boundary
		rfv2_pad128(&ctx);
	}

	rfv2_final(out, &ctx);

	if (alloc_rambox)
		free(rambox);
	else if (ctx.changes == RFV2_RAMBOX_HIST) {
		//printf("changes=%d\n", ctx.changes);
		rfv2_raminit(rambox);
	}
	else if (ctx.changes > 0) {
		//printf("changes=%d\n", ctx.changes);
		loops = ctx.changes;
		do {
			loops--;
			ctx.rambox[ctx.hist[loops]] = ctx.prev[loops];
		} while (loops);
		//rfv2_ram_test(rambox);
	}
	return 0;
}

// hash _len_ bytes from _in_ into _out_
int rfv2_hash(void *out, const void *in, size_t len, void *rambox, const void *rambox_template)
{
	return rfv2_hash2(out, in, len, rambox, rambox_template, RFV2_INIT_CRC);
}

/* scans nonces from <min> to <max> applying them to message <msg> and stopping
 * once a hash gives a result at least as good as <target>. It uses <rambox>,
 * which must have been pre-initialized, and leaves the resulting hash in
 * <hash> which must contain at least 32 bytes and be 32-bit aligned. On
 * success it returns the number of hashes attempted, or returns the opposite
 * of this number if no solution is found. This will not overflow since we only
 * cover few hashes. It only works with 32-bit
 * aligned 80-byte block headers in big endian format and places the nonce in
 * big endian format at the end of the message to hash it. In case of success,
 * the caller has to extract the nonce from the message. It also stops if
 * <stop> is non-NULL and the location it points to contains a non-null value
 * (used to interrupt scanning by another thread).
 */
int rfv2_scan_hdr(char *msg, void *rambox, uint32_t *hash, uint32_t target, uint32_t min, uint32_t max, volatile char *stop)
{
	uint32_t msgh, msgh_init, nonce, hashes;
	rfv2_ctx_t ctx;

	// pre-compute the hash state based on the constant part of the header
	msgh_init = rf_crc32_mem(0, msg, 76);

	hashes = 0;
	for (nonce = min;; nonce++) {
		msg[76] = nonce >> 24;
		msg[77] = nonce >> 16;
		msg[78] = nonce >> 8;
		msg[79] = nonce;

		msgh = rf_crc32_mem(msgh_init, msg + 76, 4);
		if (sin_scaled(msgh) != 2)
			goto next;

		rfv2_init(&ctx, RFV2_INIT_CRC, rambox);
		ctx.changes = 65535; // mark the rambox read-only

		ctx.rb_o = msgh % (ctx.rb_l / 2);
		ctx.rb_l = (ctx.rb_l / 2 - ctx.rb_o) * 2;

		/* first loop */
		rfv2_update(&ctx, msg, 80);
		rfv2_pad128(&ctx);

		/* second loop */
		rfv2_update(&ctx, msg, 80);
		rfv2_pad128(&ctx);

		/* final */
		rfv2_final(hash, &ctx);
		hashes++;

		if (__builtin_expect(rf_le32toh((uint8_t *)(hash + 7)) <= target, 0)) {
			/* make sure it's a valid hash as the read-only rambox
			 * occasionally causes invalid ones : just recompute it
			 * entirely.
			 */
			rfv2_hash2(hash, msg, 80, rambox, NULL, RFV2_INIT_CRC);
			if (rf_le32toh((uint8_t *)(hash+7)) <= target)
				return hashes;
		}
	next:
		if (nonce == max)
			return -hashes;

		if (stop && *stop)
			return -hashes;
	}
}
