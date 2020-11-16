#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

/* Move init out of loop, so init once externally,
   and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context 	blake1, blake2;
	sph_bmw512_context		bmw1, bmw2;
	sph_groestl512_context	groestl1, groestl2;
	sph_skein512_context	skein1, skein2;
	sph_jh512_context		jh1, jh2;
	sph_keccak512_context	keccak1, keccak2;
	bool init_done;
} quarkhash_context_holder;

static quarkhash_context_holder _ALIGN(128) cached_ctx;

void init_quarkhash_contexts()
{
	sph_blake512_init(&cached_ctx.blake1);
	sph_bmw512_init(&cached_ctx.bmw1);
	sph_groestl512_init(&cached_ctx.groestl1);
	sph_skein512_init(&cached_ctx.skein1);
	sph_groestl512_init(&cached_ctx.groestl2);
	sph_jh512_init(&cached_ctx.jh1);
	sph_blake512_init(&cached_ctx.blake2);
	sph_bmw512_init(&cached_ctx.bmw2);
	sph_keccak512_init(&cached_ctx.keccak1);
	sph_skein512_init(&cached_ctx.skein2);
	sph_keccak512_init(&cached_ctx.keccak2);
	sph_jh512_init(&cached_ctx.jh2);
	cached_ctx.init_done = true;
}

void quarkhash(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[16];
	quarkhash_context_holder _ALIGN(128) ctx;
	uint32_t mask = 8;

	if (cached_ctx.init_done)
		memcpy(&ctx, &cached_ctx, sizeof(cached_ctx));
	else {
		applog(LOG_ERR, "Attempt to hash quark without init!");
		exit(1);
	}

	sph_blake512 (&ctx.blake1, input, 80);
	sph_blake512_close (&ctx.blake1, hash); //0

	sph_bmw512 (&ctx.bmw1, hash, 64);
	sph_bmw512_close(&ctx.bmw1, hash); //1

	if (hash[0] & mask) {
		sph_groestl512 (&ctx.groestl1, hash, 64);
		sph_groestl512_close(&ctx.groestl1, hash); //2
	} else {
		sph_skein512 (&ctx.skein1, hash, 64);
		sph_skein512_close(&ctx.skein1, hash); //2
	}

	sph_groestl512 (&ctx.groestl2, hash, 64);
	sph_groestl512_close(&ctx.groestl2, hash); //3

	sph_jh512 (&ctx.jh1, hash, 64);
	sph_jh512_close(&ctx.jh1, hash); //4

	if (hash[0] & mask) {
		sph_blake512 (&ctx.blake2, hash, 64);
		sph_blake512_close(&ctx.blake2, hash); //5
	} else {
		sph_bmw512 (&ctx.bmw2, hash, 64);
		sph_bmw512_close(&ctx.bmw2, hash); //5
	}

	sph_keccak512 (&ctx.keccak1, hash, 64);
	sph_keccak512_close(&ctx.keccak1, hash); //6

	sph_skein512 (&ctx.skein2, hash, 64);
	sph_skein512_close(&ctx.skein2, hash); //7

	if (hash[0] & mask) {
		sph_keccak512 (&ctx.keccak2, hash, 64);
		sph_keccak512_close(&ctx.keccak2, hash); //8
	} else {
		sph_jh512 (&ctx.jh2, hash, 64);
		sph_jh512_close(&ctx.jh2, hash); //8
	}

	memcpy(state, hash, 32);
}

int scanhash_quark(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		quarkhash(hash32, endiandata);
		if (hash32[7] < Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
