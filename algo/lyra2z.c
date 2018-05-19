#include <memory.h>
//#include <mm_malloc.h>

#include "sha3/sph_blake.h"

#include "lyra2/Lyra2-xzc.h"

#include "miner.h"

void lyra2z_hash(uint64_t* wholeMatrix, void *state, const void *input)
{
#ifdef VERBOSE_HASH_TIMING
	struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    double start = spec.tv_sec + spec.tv_nsec / 1.0e9;
#endif

	sph_blake256_context     ctx_blake;

	uint32_t hashA[8], hashB[8];

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);

//	LYRA2(0, hashB, 32, hashA, 32, hashA, 32, 2, 8, 8);

	//LYRA2(wholeMatrix, hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);
	LYRA2_XZC(wholeMatrix, hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);

#ifdef VERBOSE_HASH_TIMING
    if (hash[0] % 32 == 0) {
    	clock_gettime(CLOCK_REALTIME, &spec);
    	double end = spec.tv_sec + spec.tv_nsec / 1.0e9;
    	printf("Hash time: %f ms\n", (end - start) * 1000);
    }
#endif

	memcpy(state, hashB, 32);
}

int scanhash_lyra2z(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{

	size_t size = (int64_t) ((int64_t) 16 * 16 * 96);
    //uint64_t *wholeMatrix = _mm_malloc(size, 64);
	uint64_t _ALIGN(64) wholeMatrix[24580] = {0};

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
		lyra2z_hash(wholeMatrix, hash, endiandata);
//		lyra2z_hash(0, hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			//_mm_free(wholeMatrix);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	//_mm_free(wholeMatrix);
	return 0;
}
