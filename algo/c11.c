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


void c11hash(void *output, const void *input)
{
	uint32_t _ALIGN(64) hash[16];

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;

	sph_luffa512_context		ctx_luffa1;
	sph_cubehash512_context		ctx_cubehash1;
	sph_shavite512_context		ctx_shavite1;
	sph_simd512_context		ctx_simd1;
	sph_echo512_context		ctx_echo1;

	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, 80);
	sph_blake512_close (&ctx_blake, hash);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, hash, 64);
	sph_bmw512_close(&ctx_bmw, hash);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hash, 64);
	sph_groestl512_close(&ctx_groestl, hash);

	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, hash, 64);
	sph_jh512_close(&ctx_jh, hash);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, hash, 64);
	sph_keccak512_close(&ctx_keccak, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, hash, 64);
	sph_skein512_close (&ctx_skein, hash);

	sph_luffa512_init (&ctx_luffa1);
	sph_luffa512 (&ctx_luffa1, hash, 64);
	sph_luffa512_close (&ctx_luffa1, hash);

	sph_cubehash512_init (&ctx_cubehash1);
	sph_cubehash512 (&ctx_cubehash1, hash, 64);
	sph_cubehash512_close(&ctx_cubehash1, hash);

	sph_shavite512_init (&ctx_shavite1);
	sph_shavite512 (&ctx_shavite1, hash, 64);
	sph_shavite512_close(&ctx_shavite1, hash);

	sph_simd512_init (&ctx_simd1);
	sph_simd512 (&ctx_simd1, hash, 64);
	sph_simd512_close(&ctx_simd1, hash);

	sph_echo512_init (&ctx_echo1);
	sph_echo512 (&ctx_echo1, hash, 64);
	sph_echo512_close(&ctx_echo1, hash);

	memcpy(output, hash, 32);
}

int scanhash_c11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
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
		c11hash(hash32, endiandata);

		if (hash32[7] <= Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
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
