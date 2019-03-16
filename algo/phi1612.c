/**
 * Phi1612 algo Implementation (initial LUX algo)
 */

#include <memory.h>

#include "sha3/sph_skein.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_fugue.h"
#include "sha3/gost_streebog.h"
#include "sha3/sph_echo.h"

#include "miner.h"

void phi1612_hash(void *state, const void *input)
{
	sph_skein512_context        ctx_skein;
	sph_jh512_context           ctx_jh;
	sph_cubehash512_context     ctx_cubehash;
	sph_fugue512_context        ctx_fugue;
	sph_gost512_context         ctx_gost;
	sph_echo512_context         ctx_echo;

	uint8_t _ALIGN(128) hash[64];

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, (void*) hash);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, (const void*) hash, 64);
	sph_jh512_close(&ctx_jh, (void*) hash);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, (const void*) hash, 64);
	sph_cubehash512_close(&ctx_cubehash, (void*) hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, (void*) hash);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, (const void*) hash, 64);
	sph_gost512_close(&ctx_gost, (void*) hash);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, (void*) hash);

	memcpy(state, hash, 32);
}

int scanhash_phi1612(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;

	if(opt_benchmark){
		ptarget[7] = 0x00ff;
	}

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		phi1612_hash(hash, endiandata);

		if (hash[7] < Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
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
