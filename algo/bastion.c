#include "miner.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "sha3/sph_hefty1.h"

#include "sha3/sph_luffa.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"

void bastionhash(void *output, const void *input)
{
	unsigned char _ALIGN(128) hash[64] = { 0 };

	sph_echo512_context ctx_echo;
	sph_luffa512_context ctx_luffa;
	sph_fugue512_context ctx_fugue;
	sph_whirlpool_context ctx_whirlpool;
	sph_shabal512_context ctx_shabal;
	sph_skein512_context ctx_skein;
	sph_hamsi512_context ctx_hamsi;

	HEFTY1(input, 80, hash);

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hash, 64);
	sph_luffa512_close(&ctx_luffa, hash);

	if (hash[0] & 0x8)
	{
		sph_fugue512_init(&ctx_fugue);
		sph_fugue512(&ctx_fugue, hash, 64);
		sph_fugue512_close(&ctx_fugue, hash);
	} else {
		sph_skein512_init(&ctx_skein);
		sph_skein512(&ctx_skein, hash, 64);
		sph_skein512_close(&ctx_skein, hash);
	}

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool(&ctx_whirlpool, hash, 64);
	sph_whirlpool_close(&ctx_whirlpool, hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);

	if (hash[0] & 0x8)
	{
		sph_echo512_init(&ctx_echo);
		sph_echo512(&ctx_echo, hash, 64);
		sph_echo512_close(&ctx_echo, hash);
	} else {
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512(&ctx_luffa, hash, 64);
		sph_luffa512_close(&ctx_luffa, hash);
	}

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash, 64);
	sph_shabal512_close(&ctx_shabal, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, hash, 64);
	sph_skein512_close(&ctx_skein, hash);

	if (hash[0] & 0x8)
	{
		sph_shabal512_init(&ctx_shabal);
		sph_shabal512(&ctx_shabal, hash, 64);
		sph_shabal512_close(&ctx_shabal, hash);
	} else {
		sph_whirlpool_init(&ctx_whirlpool);
		sph_whirlpool(&ctx_whirlpool, hash, 64);
		sph_whirlpool_close(&ctx_whirlpool, hash);
	}

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash, 64);
	sph_shabal512_close(&ctx_shabal, hash);

	if (hash[0] & 0x8)
	{
		sph_hamsi512_init(&ctx_hamsi);
		sph_hamsi512(&ctx_hamsi, hash, 64);
		sph_hamsi512_close(&ctx_hamsi, hash);
	} else {
		sph_luffa512_init(&ctx_luffa);
		sph_luffa512(&ctx_luffa, hash, 64);
		sph_luffa512_close(&ctx_luffa, hash);
	}

	memcpy(output, hash, 32);
}

int scanhash_bastion(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash32[8];
	uint32_t _ALIGN(64) endiandata[20];
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
		bastionhash(hash32, endiandata);
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
