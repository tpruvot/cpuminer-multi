#include "miner.h"

#include "sha3/sph_blake.h"

#include <string.h>
#include <stdint.h>
#include <memory.h>

static __thread sph_blake256_context blake_mid;
static __thread bool ctx_midstate_done = false;

void decred_hash(void *state, const void *input)
{
	#define MIDSTATE_LEN 128
	sph_blake256_context ctx;

	uint8_t *ending = (uint8_t*) input;
	ending += MIDSTATE_LEN;

	if (!ctx_midstate_done) {
		sph_blake256_init(&blake_mid);
		sph_blake256(&blake_mid, input, MIDSTATE_LEN);
		ctx_midstate_done = true;
	}
	memcpy(&ctx, &blake_mid, sizeof(blake_mid));

	sph_blake256(&ctx, ending, (180 - MIDSTATE_LEN));
	sph_blake256_close(&ctx, state);
}

void decred_hash_simple(void *state, const void *input)
{
	sph_blake256_context ctx;
	sph_blake256_init(&ctx);
	sph_blake256(&ctx, input, 180);
	sph_blake256_close(&ctx, state);
}

int scanhash_decred(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) endiandata[48];
	uint32_t _ALIGN(128) hash32[8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	#define DCR_NONCE_OFT32 35

	const uint32_t first_nonce = pdata[DCR_NONCE_OFT32];
	const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];

	uint32_t n = first_nonce;

	ctx_midstate_done = false;

#if 1
	memcpy(endiandata, pdata, 180);
#else
	for (int k=0; k < (180/4); k++)
		be32enc(&endiandata[k], pdata[k]);
#endif

#ifdef DEBUG_ALGO
	if (!thr_id) applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

	do {
		//be32enc(&endiandata[DCR_NONCE_OFT32], n);
		endiandata[DCR_NONCE_OFT32] = n;
		decred_hash(hash32, endiandata);

		if (hash32[7] <= HTarget && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			*hashes_done = n - first_nonce + 1;
#ifdef DEBUG_ALGO
			applog(LOG_BLUE, "Nonce : %08x %08x", n, swab32(n));
			applog_hash(ptarget);
			applog_compare_hash(hash32, ptarget);
#endif
			pdata[DCR_NONCE_OFT32] = n;
			return 1;
		}

		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[DCR_NONCE_OFT32] = n;
	return 0;
}
