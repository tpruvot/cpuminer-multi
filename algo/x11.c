#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"


void x11hash(void *output, const void *input)
{
	sph_blake512_context     	ctx_blake;
	sph_bmw512_context       	ctx_bmw;
	sph_groestl512_context   	ctx_groestl;
	sph_skein512_context     	ctx_skein;
	sph_jh512_context        	ctx_jh;
	sph_keccak512_context    	ctx_keccak;

	sph_luffa512_context		ctx_luffa1;
	sph_cubehash512_context		ctx_cubehash1;
	sph_shavite512_context		ctx_shavite1;
	sph_simd512_context			ctx_simd1;
	sph_echo512_context			ctx_echo1;

	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(64) hashA[16], hashB[16];

	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, 80);
	sph_blake512_close (&ctx_blake, hashA);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, hashA, 64);
	sph_bmw512_close(&ctx_bmw, hashB);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hashB, 64);
	sph_groestl512_close(&ctx_groestl, hashA);

	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, hashA, 64);
	sph_skein512_close (&ctx_skein, hashB);

	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, hashB, 64);
	sph_jh512_close(&ctx_jh, hashA);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, hashA, 64);
	sph_keccak512_close(&ctx_keccak, hashB);

	sph_luffa512_init (&ctx_luffa1);
	sph_luffa512 (&ctx_luffa1, hashB, 64);
	sph_luffa512_close (&ctx_luffa1, hashA);

	sph_cubehash512_init (&ctx_cubehash1);
	sph_cubehash512 (&ctx_cubehash1, hashA, 64);
	sph_cubehash512_close(&ctx_cubehash1, hashB);

	sph_shavite512_init (&ctx_shavite1);
	sph_shavite512 (&ctx_shavite1, hashB, 64);
	sph_shavite512_close(&ctx_shavite1, hashA);

	sph_simd512_init (&ctx_simd1);
	sph_simd512 (&ctx_simd1, hashA, 64);
	sph_simd512_close(&ctx_simd1, hashB);

	sph_echo512_init (&ctx_echo1);
	sph_echo512 (&ctx_echo1, hashB, 64);
	sph_echo512_close(&ctx_echo1, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_x11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		x11hash(hash, endiandata);

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
