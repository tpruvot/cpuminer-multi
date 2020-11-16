/**
 * Blake2-B Implementation
 * tpruvot@github 2015-2016
 */

#include "miner.h"

#include <string.h>
#include <stdint.h>

#include <crypto/blake2b.h>

#define A 64

#ifdef MIDSTATE
static __thread blake2b_ctx s_midstate;
static __thread blake2b_ctx s_ctx;
#define MIDLEN 76

static void blake2b_hash_end(uint32_t *output, const uint32_t *input)
{
        s_ctx.outlen = MIDLEN;
        memcpy(&s_ctx, &s_midstate, 32 + 16 + MIDLEN);
        blake2b_update(&s_ctx, (uint8_t*) &input[MIDLEN/4], 80 - MIDLEN);
        blake2b_final(&s_ctx, (uint8_t*) output);
}
#endif

void blake2b_hash(void *output, const void *input)
{
	uint8_t _ALIGN(A) hash[32];
	blake2b_ctx ctx;

	blake2b_init(&ctx, 32, NULL, 0);
	blake2b_update(&ctx, input, 80);
	blake2b_final(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_blake2b(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(A) vhashcpu[8];
	uint32_t _ALIGN(A) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	// midstate (untested yet)
	//blake2b_init(&s_midstate, 32, NULL, 0);
	//blake2b_update(&s_midstate, (uint8_t*) endiandata, MIDLEN);
	//memcpy(&s_ctx, &s_midstate, sizeof(blake2b_ctx));

	do {
		be32enc(&endiandata[19], n);
		//blake2b_hash_end(vhashcpu, endiandata);
		blake2b_hash(vhashcpu, endiandata);

		if (vhashcpu[7] < Htarg && fulltest(vhashcpu, ptarget)) {
			work_set_target_ratio(work, vhashcpu);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

static inline void swab256(void *dest_p, const void *src_p)
{
	uint32_t *dest = (uint32_t *)dest_p;
	const uint32_t *src = (uint32_t *)src_p;

	dest[0] = swab32(src[7]);
	dest[1] = swab32(src[6]);
	dest[2] = swab32(src[5]);
	dest[3] = swab32(src[4]);
	dest[4] = swab32(src[3]);
	dest[5] = swab32(src[2]);
	dest[6] = swab32(src[1]);
	dest[7] = swab32(src[0]);
}

int scanhash_sia(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(A) hash[8];
	uint32_t _ALIGN(A) vhashcpu[8];
	uint32_t _ALIGN(A) inputdata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[8];

	uint32_t n = first_nonce;

	memcpy(inputdata, pdata, 80);
	inputdata[11] = 0; // nbits

	do {
		inputdata[8] = n;
		blake2b_hash(hash, inputdata);
		if (swab32(hash[0]) < Htarg) {
			swab256(vhashcpu, hash);
			if (fulltest(vhashcpu, ptarget)) {
				work_set_target_ratio(work, vhashcpu);
				*hashes_done = n - first_nonce + 1;
				pdata[8] = n;
				return 1;
			}
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[8] = n;

	return 0;
}
