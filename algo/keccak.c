#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_keccak.h"

extern void keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash[32];

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 80);
    sph_keccak256_close(&ctx_keccak, hash);

	memcpy(state, hash, 32);
}

int scanhash_keccak(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {

		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		keccakhash(hash32, endiandata);

		if (hash32[7] <= Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			pdata[19] = n;
			*hashes_done = pdata[19] - first_nonce;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
