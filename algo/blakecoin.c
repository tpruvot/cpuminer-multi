#include "miner.h"

#define BLAKE32_ROUNDS 8
#include "sha3/sph_blake.h"

void blakecoin_init(void *cc);
void blakecoin(void *cc, const void *data, size_t len);
void blakecoin_close(void *cc, void *dst);

#include <string.h>
#include <stdint.h>
#include <memory.h>

static __thread sph_blake256_context blake_mid;
static __thread bool ctx_midstate_done = false;

void blakecoinhash(void *state, const void *input)
{
	sph_blake256_context ctx;

	uint8_t *ending = (uint8_t*) input;
	ending += 64;

	// do one memcopy to get a fresh context
	if (!ctx_midstate_done) {
		blakecoin_init(&blake_mid);
		blakecoin(&blake_mid, input, 64);
		ctx_midstate_done = true;
	}
	memcpy(&ctx, &blake_mid, sizeof(blake_mid));

	blakecoin(&ctx, ending, 16);
	blakecoin_close(&ctx, state);
}

int scanhash_blakecoin(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t first_nonce = pdata[19];
	const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];
	uint32_t n = first_nonce;

	ctx_midstate_done = false;

	// we need big endian data...
	for (int kk=0; kk < 19; kk++) {
		be32enc(&endiandata[kk], pdata[kk]);
	}

#ifdef DEBUG_ALGO
	applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

	do {
		be32enc(&endiandata[19], n);
		blakecoinhash(hash32, endiandata);

		if (hash32[7] <= HTarget && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			*hashes_done = n - first_nonce + 1;
			return 1;
		}

		n++; pdata[19] = n;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
