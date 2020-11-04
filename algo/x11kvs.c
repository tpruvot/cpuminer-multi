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

// Use functions defined in x11k.c
extern void *Blake512(void *oHash, const void *iHash, const size_t len);
extern void *Bmw512(void *oHash, const void *iHash, const size_t len);
extern void *Groestl512(void *oHash, const void *iHash, const size_t len);
extern void *Skein512(void *oHash, const void *iHash, const size_t len);
extern void *Jh512(void *oHash, const void *iHash, const size_t len);
extern void *Keccak512(void *oHash, const void *iHash, const size_t len);
extern void *Luffa512(void *oHash, const void *iHash, const size_t len);
extern void *Cubehash512(void *oHash, const void *iHash, const size_t len);
extern void *Shavite512(void *oHash, const void *iHash, const size_t len);
extern void *Simd512(void *oHash, const void *iHash, const size_t len);
extern void *Echo512(void *oHash, const void *iHash, const size_t len);
extern void *fnHashX11K[];
extern void processHash(void *oHash, const void *iHash, const int index, const size_t len);

extern void sha256d(unsigned char *hash, const unsigned char *data, int len);

/* ----------- Sapphire 2.0 Hash X11KVS ------------------------------------ */
/* - X11, from the original 11 algos used on DASH -------------------------- */
/* - K, from Kyanite ------------------------------------------------------- */
/* - V, from Variable, variation of the number iterations on the X11K algo - */
/* - S, from Sapphire ------------------------------------------------------ */


const unsigned int HASHX11KV_MIN_NUMBER_ITERATIONS  = 2;
const unsigned int HASHX11KV_MAX_NUMBER_ITERATIONS  = 6;
const unsigned int HASHX11KV_NUMBER_ALGOS           = 11;

const void* x11kvMemPool = NULL;

void x11kv(void *output, const void *input, int thr_id)
{
	if(x11kvMemPool == NULL) {
		x11kvMemPool = (void*) malloc(2 * 64 * 128);
	}

	void* hashA = (void*) x11kvMemPool + (thr_id * 128);
	void* hashB = (void*) x11kvMemPool + (thr_id * 128) + 64;

	unsigned char *p;

	// Iteration 0
	processHash(hashA, input, 0, 80);
	p = hashA;
	unsigned int n = HASHX11KV_MIN_NUMBER_ITERATIONS + (p[63] % (HASHX11KV_MAX_NUMBER_ITERATIONS - HASHX11KV_MIN_NUMBER_ITERATIONS + 1));

	for(int i = 1; i < n; i++) {
		p = (unsigned char *) hashA;

		processHash(hashB, hashA, p[i % 64] % HASHX11KV_NUMBER_ALGOS, 64);
       
		memcpy(hashA, hashB, 64);
	    void* t = hashA;
		hashA = hashB;
		hashB = t;
	}

	memcpy(output, hashA, 32);
}

const unsigned int HASHX11KVS_MAX_LEVEL = 4;
const unsigned int HASHX11KVS_MIN_LEVEL = 1;
const unsigned int HASHX11KVS_MAX_DRIFT = 0xF;

void x11kvshash_base(void *output, const void *input, int thr_id, unsigned int level)
{
    uint8_t* hash = (uint8_t*) malloc(32);
	x11kv(hash, input, thr_id);
    
	if (level == HASHX11KVS_MIN_LEVEL)
	{
		memcpy(output, hash, 32);
		free(hash);
		return;
	}

    uint32_t nonce = le32dec(input + 76);

    uint8_t* nextheader1 = (uint8_t*) malloc(80);
    uint8_t* nextheader2 = (uint8_t*) malloc(80);

    uint32_t nextnonce1 = nonce + (le32dec(hash + 24) % HASHX11KVS_MAX_DRIFT);
    uint32_t nextnonce2 = nonce + (le32dec(hash + 28) % HASHX11KVS_MAX_DRIFT);

    memcpy(nextheader1, input, 76);
    le32enc(nextheader1 + 76, nextnonce1);

    memcpy(nextheader2, input, 76);
    le32enc(nextheader2 + 76, nextnonce2);

	uint8_t* hash1 = (uint8_t*) malloc(32);
	uint8_t* hash2 = (uint8_t*) malloc(32);

	x11kvshash_base(hash1, nextheader1, thr_id, level - 1);
    x11kvshash_base(hash2, nextheader2, thr_id, level - 1);

	// Concat hash, hash1 and hash2
	uint8_t* hashConcated = (uint8_t*) malloc(96);
	memcpy(hashConcated, hash, 32);
	memcpy(hashConcated + 32, hash1, 32);
	memcpy(hashConcated + 32 + 32, hash2, 32);

	sha256d(output, hashConcated, 96);

	memcpy(output, hash, 32);

	free(hash);
	free(hash1);
	free(hash2);
	free(nextheader1);
	free(nextheader2);
	free(hashConcated);
}

void x11kvshash(void *output, const void *input, int thr_id)
{
	x11kvshash_base(output, input, thr_id, HASHX11KVS_MAX_LEVEL);
}

int scanhash_x11kvs(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
		x11kvshash(hash, endiandata, thr_id);

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

