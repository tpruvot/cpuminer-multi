#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_shabal.h"
#include "crypto/mshabal.h"

static __thread uint32_t _ALIGN(128) M[65536][8];

void axiomhash(void *output, const void *input)
{
	sph_shabal256_context ctx;
	const int N = 65536;

	sph_shabal256_init(&ctx);
	sph_shabal256(&ctx, input, 80);
	sph_shabal256_close(&ctx, M[0]);

	for(int i = 1; i < N; i++) {
		//sph_shabal256_init(&ctx);
		sph_shabal256(&ctx, M[i-1], 32);
		sph_shabal256_close(&ctx, M[i]);
	}

	for(int b = 0; b < N; b++)
	{
		const int p = b > 0 ? b - 1 : 0xFFFF;
		const int q = M[p][0] % 0xFFFF;
		const int j = (b + q) % N;

		//sph_shabal256_init(&ctx);
#if 0
		sph_shabal256(&ctx, M[p], 32);
		sph_shabal256(&ctx, M[j], 32);
#else
		uint8_t _ALIGN(128) hash[64];
		memcpy(hash, M[p], 32);
		memcpy(&hash[32], M[j], 32);
		sph_shabal256(&ctx, hash, 64);
#endif
		sph_shabal256_close(&ctx, M[b]);
	}
	memcpy(output, M[N-1], 32);
}

typedef uint32_t hash_t[8];

void axiomhash4way(mshabal_context* ctx_org, void* memspace, const void *input1, void *result1, const void *input2, void *result2, const void *input3, void *result3, const void *input4, void *result4)
{
	mshabal_context ctx_shabal;
	int i, b;
	hash_t *hash1, *hash2, *hash3, *hash4;

	hash1 = memspace;
	memset(hash1, 0, 65536 * 32 * 4);
	hash2 = &hash1[65536 * 1];
	hash3 = &hash1[65536 * 2];
	hash4 = &hash1[65536 * 3];

	memcpy(&ctx_shabal, ctx_org, sizeof(mshabal_context));
	mshabal(&ctx_shabal, input1, input2, input3, input4, 80);
	mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, hash1[0], hash2[0], hash3[0], hash4[0]);

	for (i = 1; i < 65536; i++)
	{
		memcpy(&ctx_shabal, ctx_org, sizeof(mshabal_context));
		mshabal(&ctx_shabal, hash1[i - 1], hash2[i - 1], hash3[i - 1], hash4[i - 1], 32);
		mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, hash1[i], hash2[i], hash3[i], hash4[i]);
	}

	for (b = 0; b < 65536; b++)
	{
		int p = b > 0 ? b - 1 : 0xffff;
		int q1 = hash1[p][0] % 0xffff;
		int j1 = (b + q1) % 65536;
		int q2 = hash2[p][0] % 0xffff;
		int j2 = (b + q2) % 65536;
		int q3 = hash3[p][0] % 0xffff;
		int j3 = (b + q3) % 65536;
		int q4 = hash4[p][0] % 0xffff;
		int j4 = (b + q4) % 65536;

		uint8_t _hash1[64];
		uint8_t _hash2[64];
		uint8_t _hash3[64];
		uint8_t _hash4[64];

		memcpy(_hash1, hash1[p], 32);
		memcpy(&_hash1[32], hash1[j1], 32);
		memcpy(_hash2, hash2[p], 32);
		memcpy(&_hash2[32], hash2[j2], 32);
		memcpy(_hash3, hash3[p], 32);
		memcpy(&_hash3[32], hash3[j3], 32);
		memcpy(_hash4, hash4[p], 32);
		memcpy(&_hash4[32], hash4[j4], 32);

		memcpy(&ctx_shabal, ctx_org, sizeof(mshabal_context));
		mshabal(&ctx_shabal, _hash1, _hash2, _hash3, _hash4, 64);
		mshabal_close(&ctx_shabal, 0, 0, 0, 0, 0, hash1[b], hash2[b], hash3[b], hash4[b]);
	}

	memcpy(result1, hash1[0xffff], 32);
	memcpy(result2, hash2[0xffff], 32);
	memcpy(result3, hash3[0xffff], 32);
	memcpy(result4, hash4[0xffff], 32);
}


int scanhash_axiom(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash64_1[8], hash64_2[8], hash64_3[8], hash64_4[8];
	uint32_t _ALIGN(128) endiandata_1[20], endiandata_2[20], endiandata_3[20], endiandata_4[20];
	mshabal_context ctx_org;
	void* memspace;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	// to avoid small chance of generating duplicate shares
	max_nonce = (max_nonce / 4) * 4;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata_1[i], pdata[i]);
	}

	memcpy(endiandata_2, endiandata_1, sizeof(endiandata_1));
	memcpy(endiandata_3, endiandata_1, sizeof(endiandata_1));
	memcpy(endiandata_4, endiandata_1, sizeof(endiandata_1));

	mshabal_init(&ctx_org, 256);
	memspace = malloc(65536 * 32 * 4);

	do {
		be32enc(&endiandata_1[19], n);
		be32enc(&endiandata_2[19], n + 1);
		be32enc(&endiandata_3[19], n + 2);
		be32enc(&endiandata_4[19], n + 3);
		//axiomhash(hash64_1, endiandata_1);
		axiomhash4way(&ctx_org, memspace, endiandata_1, hash64_1, endiandata_2, hash64_2, endiandata_3, hash64_3, endiandata_4, hash64_4);
		if (hash64_1[7] < Htarg && fulltest(hash64_1, ptarget)) {
			*hashes_done = n - first_nonce + 4;
			pdata[19] = n;
			free(memspace);
			return true;
		}
		if (hash64_2[7] < Htarg && fulltest(hash64_2, ptarget)) {
			*hashes_done = n - first_nonce + 4;
			pdata[19] = n + 1;
			free(memspace);
			return true;
		}
		if (hash64_3[7] < Htarg && fulltest(hash64_3, ptarget)) {
			*hashes_done = n - first_nonce + 4;
			pdata[19] = n + 2;
			free(memspace);
			return true;
		}
		if (hash64_4[7] < Htarg && fulltest(hash64_4, ptarget)) {
			*hashes_done = n - first_nonce + 4;
			pdata[19] = n + 3;
			free(memspace);
			return true;
		}
		
		n += 4;
		//n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 4;
	pdata[19] = n;
	free(memspace);
	return 0;
}
