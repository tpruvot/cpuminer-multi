#include "miner.h"

#include <stdlib.h>
#include <string.h>
#include "inttypes.h"

/* Hard-coded scrypt parameteres r and p - mikaelh */
#define SCRYPT_R 1
#define SCRYPT_P 1

/* Only the instrinsics versions are optimized for hard-coded values - mikaelh */
#define CPU_X86_FORCE_INTRINSICS

#undef SCRYPT_KECCAK512
#undef SCRYPT_CHACHA
#undef SCRYPT_CHOOSE_COMPILETIME
#define SCRYPT_KECCAK512
#define SCRYPT_CHACHA
#define SCRYPT_CHOOSE_COMPILETIME

//#include "scrypt-jane.h"
#include "../scryptjane/scrypt-jane-portable.h"
#include "../scryptjane/scrypt-jane-hash.h"
#include "../scryptjane/scrypt-jane-romix.h"
#include "../scryptjane/scrypt-jane-test-vectors.h"


#define scrypt_maxN 30  /* (1 << (30 + 1)) = ~2 billion */
#if (SCRYPT_BLOCK_BYTES == 64)
#define scrypt_r_32kb 8 /* (1 << 8) = 256 * 2 blocks in a chunk * 64 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 128)
#define scrypt_r_32kb 7 /* (1 << 7) = 128 * 2 blocks in a chunk * 128 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 256)
#define scrypt_r_32kb 6 /* (1 << 6) = 64 * 2 blocks in a chunk * 256 bytes = Max of 32kb in a chunk */
#elif (SCRYPT_BLOCK_BYTES == 512)
#define scrypt_r_32kb 5 /* (1 << 5) = 32 * 2 blocks in a chunk * 512 bytes = Max of 32kb in a chunk */
#endif
#define scrypt_maxr scrypt_r_32kb /* 32kb */
#define scrypt_maxp 25  /* (1 << 25) = ~33 million */

typedef struct scrypt_aligned_alloc_t {
	uint8_t *mem, *ptr;
} scrypt_aligned_alloc;

static int
scrypt_alloc(uint64_t size, scrypt_aligned_alloc *aa) {
	static const size_t max_alloc = (size_t)-1;
	size += (SCRYPT_BLOCK_BYTES - 1);
	if (size > max_alloc)
		return 0; // scrypt_fatal_error("scrypt: not enough address space on this CPU to allocate required memory");
	aa->mem = (uint8_t *)malloc((size_t)size);
	aa->ptr = (uint8_t *)(((size_t)aa->mem + (SCRYPT_BLOCK_BYTES - 1)) & ~(SCRYPT_BLOCK_BYTES - 1));
	if (!aa->mem)
		return 0; // scrypt_fatal_error("scrypt: out of memory");
	return 1;
}

static void
scrypt_free(scrypt_aligned_alloc *aa) {
	free(aa->mem);
}

void
scrypt_N_1_1(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t N, uint8_t *out, size_t bytes, uint8_t *X, uint8_t *Y, uint8_t *V) {
	uint32_t chunk_bytes, i;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
	scrypt_ROMixfn scrypt_ROMix = scrypt_getROMix();
#endif

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;

	/* 1: X = PBKDF2(password, salt) */
	scrypt_pbkdf2_1(password, password_len, salt, salt_len, X, chunk_bytes * p);

	/* 2: X = ROMix(X) */
	for (i = 0; i < p; i++)
		scrypt_ROMix_1((scrypt_mix_word_t *)(X + (chunk_bytes * i)), (scrypt_mix_word_t *)Y, (scrypt_mix_word_t *)V, N);

	/* 3: Out = PBKDF2(password, X) */
	scrypt_pbkdf2_1(password, password_len, X, chunk_bytes * p, out, bytes);

#ifdef SCRYPT_PREVENT_STATE_LEAK
	/* This is an unnecessary security feature - mikaelh */
	scrypt_ensure_zero(Y, (p + 1) * chunk_bytes);
#endif
}


//  increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = 30;

unsigned char GetNfactor(unsigned int nTimestamp, unsigned int ntime) {
	int l = 0;
	unsigned long int s;
	int n;
	unsigned char N;

	if (nTimestamp <= ntime)
		return 4;

	s = nTimestamp - ntime;
	while ((s >> 1) > 3) {
		l += 1;
		s >>= 1;
	}

	s &= 3;

	n = (l * 170 + s * 25 - 2320) / 100;

	if (n < 0) n = 0;

	if (n > 255) {
		n = 255;
		// printf("GetNfactor(%d) - something wrong(n == %d)\n", nTimestamp, n);
	}

	N = (unsigned char)n;
	//printf("GetNfactor: %d -> %d %d : %d / %d\n", nTimestamp - nChainStartTime, l, s, n, min(max(N, minNfactor), maxNfactor));

	if (N<minNfactor) return minNfactor;
	if (N>maxNfactor) return maxNfactor;
	return N;
}


int scanhash_scryptjane(int Nfactor, int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t N, chunk_bytes;
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	//Nfactor = GetNfactor(data[17], ntime);
	//if (Nfactor > scrypt_maxN) {
	//	return 1;
	//	//scrypt_fatal_error("scrypt: N out of range");
	//}

	N = (1 << (Nfactor + 1));

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	if (!scrypt_alloc((uint64_t)N * chunk_bytes, &V)) return 1;
	if (!scrypt_alloc((p + 1) * chunk_bytes, &YX)) {
		scrypt_free(&V);
		return 1;
	}

	Y = YX.ptr;
	X = Y + chunk_bytes;

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);

		scrypt_N_1_1((unsigned char *)endiandata, 80,
			(unsigned char *)endiandata, 80,
			N, (unsigned char *)hash, 32, X, Y, V.ptr);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			scrypt_free(&V);
			scrypt_free(&YX);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;

	scrypt_free(&V);
	scrypt_free(&YX);
	return 0;
}

/* simple cpu test (util.c) */
void scryptjanehash(void *output, const void *input, uint32_t Nfactor)
{
	scrypt_aligned_alloc YX, V;
	uint8_t *X, *Y;
	uint32_t chunk_bytes;
	uint32_t N = (1 << (Nfactor + 1));
	const uint32_t r = SCRYPT_R;
	const uint32_t p = SCRYPT_P;

	memset(output, 0, 32);

	chunk_bytes = SCRYPT_BLOCK_BYTES * r * 2;
	if (!scrypt_alloc((uint64_t)N * chunk_bytes, &V)) return;
	if (!scrypt_alloc((p + 1) * chunk_bytes, &YX)) {
		scrypt_free(&V);
		return;
	}

	Y = YX.ptr;
	X = Y + chunk_bytes;

	scrypt_N_1_1((unsigned char*)input, 80, (unsigned char*)input, 80,
		N, (unsigned char*)output, 32, X, Y, V.ptr);

	scrypt_free(&V);
	scrypt_free(&YX);
}
