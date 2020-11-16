#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha3/sph_groestl.h"

// static __thread sph_groestl512_context ctx;

void groestlhash(void *output, const void *input)
{
	uint32_t _ALIGN(32) hash[16];
	sph_groestl512_context ctx;

	// memset(&hash[0], 0, sizeof(hash));

	sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, input, 80);
	sph_groestl512_close(&ctx, hash);

	//sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, hash, 64);
	sph_groestl512_close(&ctx, hash);

	memcpy(output, hash, 32);
}

int scanhash_groestl(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		groestlhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
