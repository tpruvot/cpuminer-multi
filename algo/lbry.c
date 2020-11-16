/**
 * Lbry sph Implementation
 * tpruvot@github July 2016
 */

#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_sha2.h"
#include "sha3/sph_ripemd.h"

#define A 64

typedef struct {
	sph_sha256_context sha256;
	sph_sha512_context sha512;
	sph_ripemd160_context ripemd;
} lbryhash_context_holder;

static __thread lbryhash_context_holder ctx;
static __thread bool ctx_init = false;

static void lbry_initstate()
{
	sph_sha256_init(&ctx.sha256);
	sph_sha512_init(&ctx.sha512);
	sph_ripemd160_init(&ctx.ripemd);
	ctx_init = true;
}

void lbry_hash(void* output, const void* input)
{
	uint32_t _ALIGN(A) hashA[16];
	uint32_t _ALIGN(A) hashB[8];
	uint32_t _ALIGN(A) hashC[8];

	//memset(&hashA[8], 0, 32);

	// sha256d
	sph_sha256(&ctx.sha256, input, 112);
	sph_sha256_close(&ctx.sha256, hashA);
	sph_sha256(&ctx.sha256, hashA, 32);
	sph_sha256_close(&ctx.sha256, hashA);

	sph_sha512(&ctx.sha512, hashA, 32);
	sph_sha512_close(&ctx.sha512, hashA);

	sph_ripemd160(&ctx.ripemd, hashA, 32);
	sph_ripemd160_close(&ctx.ripemd, hashB);

	sph_ripemd160(&ctx.ripemd, &hashA[8], 32); // weird
	sph_ripemd160_close(&ctx.ripemd, hashC);

	sph_sha256(&ctx.sha256, hashB, 20);
	sph_sha256(&ctx.sha256, hashC, 20);
	sph_sha256_close(&ctx.sha256, hashA);

	sph_sha256(&ctx.sha256, hashA, 32);
	sph_sha256_close(&ctx.sha256, hashA);

	memcpy(output, hashA, 32);
}

int scanhash_lbry(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(A) vhashcpu[8];
	uint32_t _ALIGN(A) endiandata[28];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[27];

	uint32_t n = first_nonce;

	for (int i=0; i < 27; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	if (!ctx_init) lbry_initstate();

	do {
		be32enc(&endiandata[27], n);
		lbry_hash(vhashcpu, endiandata);

		if (vhashcpu[7] <= Htarg && fulltest(vhashcpu, ptarget)) {
			work_set_target_ratio(work, vhashcpu);
			*hashes_done = n - first_nonce + 1;
			work->resnonce = pdata[27] =  n; // to check
			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[27] = n;

	return 0;
}
