#include <memory.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_bmw.h"

#include "lyra2/Lyra2.h"

#include "miner.h"

void lyra2v3_hash(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[8], hashB[8];

	sph_blake256_context     ctx_blake;
	sph_cubehash256_context  ctx_cubehash;
	sph_bmw256_context       ctx_bmw;

	//sph_blake256_set_rounds(14);

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hash);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	sph_cubehash256_init(&ctx_cubehash);
	sph_cubehash256(&ctx_cubehash, hashB, 32);
	sph_cubehash256_close(&ctx_cubehash, hash);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	sph_bmw256_init(&ctx_bmw);
	sph_bmw256(&ctx_bmw, hashB, 32);
	sph_bmw256_close(&ctx_bmw, hash);

	memcpy(state, hash, 32);
}

int scanhash_lyra2v3(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], nonce);
		lyra2v3_hash(hash, endiandata);

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
