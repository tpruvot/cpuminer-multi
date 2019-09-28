#include <stdint.h>

// Two round implementation optimized for x86_64+AES-NI and ARMv8+crypto
// extensions. Test pattern :
//
// Plaintext:
// 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//
// Ciphertext (encryption result):
// 0x16, 0xcd, 0xb8, 0x7a, 0xc6, 0xae, 0xdb, 0x19, 0xe9, 0x32, 0x47, 0x85, 0x39, 0x51, 0x24, 0xe6
//
// Plaintext (decryption result):
// 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

/* Rijndael's substitution box for sub_bytes step */
static uint8_t SBOX[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*--- The parts below are not used when crypto extensions are available ---*/
/* Use -march=armv8-a+crypto on ARMv8 to use crypto extensions */
/* Use -maes on x86_64 to use AES-NI */
#if defined(RF_NOASM) || (!defined(__aarch64__) || !defined(__ARM_FEATURE_CRYPTO)) && (!defined(__x86_64__) || !defined(__AES__))

/* shifts to do for shift_rows step */
static uint8_t shifts[16] = {
	 0,  5, 10, 15,
	 4,  9, 14,  3,
	 8, 13,  2,  7,
	12,  1,  6, 11
};

/* add the round key to the state with simple XOR operation */
static void add_round_key(uint8_t * state, const uint8_t * rkey)
{
	uint8_t i;

	for (i = 0; i < 16; i++)
		state[i] ^= rkey[i];
}

/* substitute all bytes using Rijndael's substitution box */
static void sub_bytes(uint8_t * state)
{
	uint8_t i;

	for (i = 0; i < 16; i++)
		state[i] = SBOX[state[i]];
}

/* imagine the state not as 1-dimensional, but a 4x4 grid;
 * this step shifts the rows of this grid around */
static void shift_rows(uint8_t * state)
{
	uint8_t temp[16];
	uint8_t i;

	for (i = 0; i < 16; i++)
		temp[i] = state[shifts[i]];

	for (i = 0; i < 16; i++)
		state[i] = temp[i];
}

/* mix columns */
static void mix_columns(uint8_t * state)
{
	uint8_t a[4];
	uint8_t b[4];
	uint8_t h, i, k;

	for (k = 0; k < 4; k++) {
		for (i = 0; i < 4; i++) {
			a[i] = state[i + 4 * k];
			h = state[i + 4 * k] & 0x80; /* hi bit */
			b[i] = state[i + 4 * k] << 1;

			if (h == 0x80)
				b[i] ^= 0x1b; /* Rijndael's Galois field */
		}

		state[4 * k]     = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		state[1 + 4 * k] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		state[2 + 4 * k] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		state[3 + 4 * k] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
	}
}
#endif // (!defined(__aarch64__) || !defined(__ARM_FEATURE_CRYPTO)) && (!defined(__x86_64__) || !defined(__AES__))


/* key schedule stuff */

/* simple function to rotate 4 byte array */
static inline uint32_t rotate32(uint32_t in)
{
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	in = (in >> 8) | (in << 24);
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	in = (in << 8) | (in >> 24);
#else
	uint8_t *b = (uint8_t *)&in, temp = b[0];
	b[0] = b[1]; b[1] = b[2]; b[2] = b[3]; b[3] = temp;
#endif
	return in;
}

/* key schedule core operation */
static inline uint32_t sbox(uint32_t in, uint8_t n)
{
	in = (SBOX[in & 255]) | (SBOX[(in >> 8) & 255] << 8) | (SBOX[(in >> 16) & 255] << 16) | (SBOX[(in >> 24) & 255] << 24);
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	in ^= n;
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	in ^= n << 24;
#else
	*(uint8_t *)&in ^= n;
#endif
	return in;
}

// this version is optimized for exactly two rounds.
// _state_ must be 16-byte aligned.
static inline void aes2r_encrypt(uint8_t * state, const uint8_t * key)
{
	uint32_t RF_ALIGN(16) key_schedule[12];
	uint32_t t;

	/* initialize key schedule; its first 16 bytes are the key */
	key_schedule[0] = ((uint32_t *)key)[0];
	key_schedule[1] = ((uint32_t *)key)[1];
	key_schedule[2] = ((uint32_t *)key)[2];
	key_schedule[3] = ((uint32_t *)key)[3];
	t = key_schedule[3];

	t = rotate32(t);
	t = sbox(t, 1);
	t = key_schedule[4]  = key_schedule[0] ^ t;
	t = key_schedule[5]  = key_schedule[1] ^ t;
	t = key_schedule[6]  = key_schedule[2] ^ t;
	t = key_schedule[7]  = key_schedule[3] ^ t;

	t = rotate32(t);
	t = sbox(t, 2);
	t = key_schedule[8]  = key_schedule[4] ^ t;
	t = key_schedule[9]  = key_schedule[5] ^ t;
	t = key_schedule[10] = key_schedule[6] ^ t;
	t = key_schedule[11] = key_schedule[7] ^ t;

	// Use -march=armv8-a+crypto+crc to get this one
#if !defined(RF_NOASM) && defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
	__asm__ volatile(
		"ld1   {v0.16b},[%0]        \n"
		"ld1   {v1.16b,v2.16b,v3.16b},[%1]  \n"
		"aese  v0.16b,v1.16b        \n" // round1: add_round_key,sub_bytes,shift_rows
		"aesmc v0.16b,v0.16b        \n" // round1: mix_columns
		"aese  v0.16b,v2.16b        \n" // round2: add_round_key,sub_bytes,shift_rows
		"eor   v0.16b,v0.16b,v3.16b \n" // finish: add_round_key
		"st1   {v0.16b},[%0]        \n"
		: /* only output is in *state */
		: "r"(state), "r"(key_schedule)
		: "v0", "v1", "v2", "v3", "cc", "memory");

	// Use -maes to get this one
#elif !defined(RF_NOASM) && defined(__x86_64__) && defined(__AES__)
	__asm__ volatile(
		"movups (%0),  %%xmm0     \n"
		"movups (%1),  %%xmm1     \n"
		"pxor   %%xmm1,%%xmm0     \n" // add_round_key(state, key_schedule)
		"movups 16(%1),%%xmm2     \n"
		"movups 32(%1),%%xmm1     \n"
		"aesenc %%xmm2,%%xmm0     \n" // first round
		"aesenclast %%xmm1,%%xmm0 \n" // final round
		"movups %%xmm0, (%0)  \n"
		: /* only output is in *state */
		: "r"(state), "r" (key_schedule)
		: "xmm0", "xmm1", "xmm2", "cc", "memory");
#else
	/* first round of the algorithm */
	add_round_key(state, (const uint8_t*)&key_schedule[0]);
	sub_bytes(state);
	shift_rows(state);
	mix_columns(state);
	add_round_key(state, (const uint8_t*)&key_schedule[4]);

	/* final round of the algorithm */
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, (const uint8_t*)&key_schedule[8]);
#endif
}
