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

void *Blake512(void *oHash, const void *iHash, const size_t len)
{
	sph_blake512_context ctx_blake;

	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, iHash, len);
	sph_blake512_close (&ctx_blake, oHash);
}

void *Bmw512(void *oHash, const void *iHash, const size_t len)
{
	sph_bmw512_context ctx_bmw;

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, iHash, len);
	sph_bmw512_close(&ctx_bmw, oHash);
}

void *Groestl512(void *oHash, const void *iHash, const size_t len)
{
	sph_groestl512_context ctx_groestl;

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, iHash, len);
	sph_groestl512_close(&ctx_groestl, oHash);
}

void *Skein512(void *oHash, const void *iHash, const size_t len)
{
	sph_skein512_context ctx_skein;

	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, iHash, len);
	sph_skein512_close (&ctx_skein, oHash);
}

void *Jh512(void *oHash, const void *iHash, const size_t len)
{
	sph_jh512_context ctx_jh;

	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, iHash, len);
	sph_jh512_close(&ctx_jh, oHash);
}

void *Keccak512(void *oHash, const void *iHash, const size_t len)
{
	sph_keccak512_context ctx_keccak;

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, iHash, len);
	sph_keccak512_close(&ctx_keccak, oHash);
}

void *Luffa512(void *oHash, const void *iHash, const size_t len)
{
	sph_luffa512_context ctx_luffa1;

	sph_luffa512_init (&ctx_luffa1);
	sph_luffa512 (&ctx_luffa1, iHash, len);
	sph_luffa512_close (&ctx_luffa1, oHash);
}

void *Cubehash512(void *oHash, const void *iHash, const size_t len)
{
	sph_cubehash512_context	ctx_cubehash1;

	sph_cubehash512_init (&ctx_cubehash1);
	sph_cubehash512 (&ctx_cubehash1, iHash, len);
	sph_cubehash512_close(&ctx_cubehash1, oHash);
}

void *Shavite512(void *oHash, const void *iHash, const size_t len)
{
	sph_shavite512_context ctx_shavite1;

	sph_shavite512_init (&ctx_shavite1);
	sph_shavite512 (&ctx_shavite1, iHash, len);
	sph_shavite512_close(&ctx_shavite1, oHash);
}

void *Simd512(void *oHash, const void *iHash, const size_t len)
{
	sph_simd512_context	ctx_simd1;

	sph_simd512_init (&ctx_simd1);
	sph_simd512 (&ctx_simd1, iHash, len);
	sph_simd512_close(&ctx_simd1, oHash);
}

void *Echo512(void *oHash, const void *iHash, const size_t len)
{
	sph_echo512_context	ctx_echo1;

	sph_echo512_init (&ctx_echo1);
	sph_echo512 (&ctx_echo1, iHash, len);
	sph_echo512_close(&ctx_echo1, oHash);
}

void *fnHashX11K[] = {
	Blake512,
	Bmw512,
	Groestl512,
	Skein512,
	Jh512,
	Keccak512,
	Luffa512,
	Cubehash512,
	Shavite512,
	Simd512,
	Echo512,
};

void processHash(void *oHash, const void *iHash, const int index, const size_t len)
{
	void (*hashX11k)(void *oHash, const void *iHash, const size_t len);

	hashX11k = fnHashX11K[index];
	(*hashX11k)(oHash, iHash, len);
}

const void* memPool = NULL;

void x11khash(void *output, const void *input, int thr_id)
{
	const int HASHX11K_NUMBER_ITERATIONS = 64;
	const int HASHX11K_NUMBER_ALGOS = 11;

	// uint32_t _ALIGN(64) hashA[64/4], hashB[64/4];
	if(memPool == NULL) {
		memPool = (void*) malloc(2 * 64 * 128);
	}

	void* hashA = (void*) memPool + (thr_id * 128);
	void* hashB = (void*) memPool + (thr_id * 128) + 64;

	unsigned char *p;

	// Iteration 0
	processHash(hashA, input, 0, 80);

	for(int i = 1; i < HASHX11K_NUMBER_ITERATIONS; i++) {
        // unsigned char * p = hashA;
		p = (unsigned char *) hashA;

		processHash(hashB, hashA, p[i] % HASHX11K_NUMBER_ALGOS, 64);
       
		memcpy(hashA, hashB, 64);
	    void* t = hashA;
		hashA = hashB;
		hashB = t;
	}

	memcpy(output, hashA, 32);
}

int scanhash_x11k(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
		x11khash(hash, endiandata, thr_id);

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

