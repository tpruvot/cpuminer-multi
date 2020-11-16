#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>

// Machinecoin Genesis Timestamp
#define HASH_FUNC_BASE_TIMESTAMP 1389040865

#define HASH_FUNC_COUNT 8
#define HASH_FUNC_COUNT_PERMUTATIONS 40320

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread int permutation[HASH_FUNC_COUNT] = { 0 };

// helpers
static void swap(int *a, int *b) {
	int c = *a;
	*a = *b;
	*b = c;
}

static void reverse(int *pbegin, int *pend) {
	while ( (pbegin != pend) && (pbegin != --pend) )
		swap(pbegin++, pend);
}

static void next_permutation(int *pbegin, int *pend) {
	if (pbegin == pend)
		return;

	int *i = pbegin;
	++i;
	if (i == pend)
		return;

	i = pend;
	--i;

	while (1) {
		int *j = i;
		--i;

		if (*i < *j) {
			int *k = pend;

			while (!(*i < *--k))
				/* pass */;

			swap(i, k);
			reverse(j, pend);
			return; // true
		}

		if (i == pbegin) {
			reverse(pbegin, pend);
			return; // false
		}
	}
}

void timetravel_hash(void *output, const void *input)
{
	uint32_t _ALIGN(64) hash[16 * HASH_FUNC_COUNT];
	uint32_t *hashA, *hashB;
	uint32_t dataLen = 64;
	uint32_t *work_data = (uint32_t *)input;
	const uint32_t timestamp = work_data[17];

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_luffa512_context     ctx_luffa;
	sph_cubehash512_context  ctx_cubehash;

	// We want to permute algorithms. To get started we
	// initialize an array with a sorted sequence of unique
	// integers where every integer represents its own algorithm.
	if (timestamp != s_ntime) {
		int steps = (int) (timestamp - HASH_FUNC_BASE_TIMESTAMP) % HASH_FUNC_COUNT_PERMUTATIONS;
		for (int i = 0; i < HASH_FUNC_COUNT; i++) {
			permutation[i] = i;
		}
		for (int i = 0; i < steps; i++) {
			next_permutation(permutation, permutation + HASH_FUNC_COUNT);
		}
		s_ntime = timestamp;
	}

	for (int i = 0; i < HASH_FUNC_COUNT; i++) {
		if (i == 0) {
			dataLen = 80;
			hashA = work_data;
		} else {
			dataLen = 64;
			hashA = &hash[16 * (i - 1)];
		}
		hashB = &hash[16 * i];

		switch(permutation[i]) {
			case 0:
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, hashA, dataLen);
				sph_blake512_close(&ctx_blake, hashB);
				break;
			case 1:
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512 (&ctx_bmw, hashA, dataLen);
				sph_bmw512_close(&ctx_bmw, hashB);
				break;
			case 2:
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512 (&ctx_groestl, hashA, dataLen);
				sph_groestl512_close(&ctx_groestl, hashB);
				break;
			case 3:
				sph_skein512_init(&ctx_skein);
				sph_skein512 (&ctx_skein, hashA, dataLen);
				sph_skein512_close(&ctx_skein, hashB);
				break;
			case 4:
				sph_jh512_init(&ctx_jh);
				sph_jh512 (&ctx_jh, hashA, dataLen);
				sph_jh512_close(&ctx_jh, hashB);
				break;
			case 5:
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512 (&ctx_keccak, hashA, dataLen);
				sph_keccak512_close(&ctx_keccak, hashB);
				break;
			case 6:
				sph_luffa512_init(&ctx_luffa);
				sph_luffa512 (&ctx_luffa, hashA, dataLen);
				sph_luffa512_close(&ctx_luffa, hashB);
				break;
			case 7:
				sph_cubehash512_init(&ctx_cubehash);
				sph_cubehash512 (&ctx_cubehash, hashA, dataLen);
				sph_cubehash512_close(&ctx_cubehash, hashB);
				break;
			default:
				break;
		}
	}

	memcpy(output, &hash[16 * (HASH_FUNC_COUNT - 1)], 32);
}

int scanhash_timetravel(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		timetravel_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
