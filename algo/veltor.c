#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sha3/sph_skein.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_shabal.h>
#include <sha3/gost_streebog.h>

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_skein512_context    skein1;
	sph_shavite512_context  shavite1;
	sph_shabal512_context   shabal1;
	sph_gost512_context     gost1;
} Xhash_context_holder;

static __thread Xhash_context_holder base_contexts;
static __thread bool init = false;

static void init_Xhash_contexts()
{
	sph_skein512_init(&base_contexts.skein1);
	sph_shavite512_init(&base_contexts.shavite1);
	sph_shabal512_init(&base_contexts.shabal1);
	sph_gost512_init(&base_contexts.gost1);
	init = true;
}

void veltor_hash(void *output, const void *input)
{
	Xhash_context_holder ctx;

	uint32_t hashA[16];

	if (!init) init_Xhash_contexts();

	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	sph_skein512(&ctx.skein1, input, 80);
	sph_skein512_close(&ctx.skein1, hashA);

	sph_shavite512(&ctx.shavite1, hashA, 64);
	sph_shavite512_close(&ctx.shavite1, hashA);

	sph_shabal512(&ctx.shabal1, hashA, 64);
	sph_shabal512_close(&ctx.shabal1, hashA);

	sph_gost512(&ctx.gost1, hashA, 64);
	sph_gost512_close(&ctx.gost1, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_veltor(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	// we need bigendian data...
	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}
	do {
		be32enc(&endiandata[19], nonce);
		veltor_hash(hash, endiandata);

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
