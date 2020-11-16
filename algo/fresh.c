#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

//#define DEBUG_ALGO

extern void freshhash(void* output, const void* input, uint32_t len)
{
	unsigned char hash[128]; // uint32_t hashA[16], hashB[16];
	#define hashA hash
	#define hashB hash+64

	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, input, len);
	sph_shavite512_close(&ctx_shavite, hashA);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hashA, 64);
	sph_simd512_close(&ctx_simd, hashB);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hashB, 64);
	sph_shavite512_close(&ctx_shavite, hashA);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hashA, 64);
	sph_simd512_close(&ctx_simd, hashB);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hashB, 64);
	sph_echo512_close(&ctx_echo, hashA);

	memcpy(output, hash, 32);
}

int scanhash_fresh(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	const uint32_t len = 80;
	uint32_t n = pdata[19] - 1;

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

	// we need bigendian data...
	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
#ifdef DEBUG_ALGO
	if (Htarg != 0)
		printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < 6; m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				freshhash(hash32, endiandata, len);
#ifndef DEBUG_ALGO
				if ((!(hash32[7] & mask)) && fulltest(hash32, ptarget)) {
					work_set_target_ratio(work, hash32);
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash32[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash32, ptarget)) {
						work_set_target_ratio(work, hash32);
						*hashes_done = n - first_nonce + 1;
						return 1;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
