/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 */
#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/sph_sha2.h>

enum Algo {
	BLAKE = 0,
	BMW,
	GROESTL,
	JH,
	KECCAK,
	SKEIN,
	LUFFA,
	CUBEHASH,
	SHAVITE,
	SIMD,
	ECHO,
	HAMSI,
	FUGUE,
	SHABAL,
	WHIRLPOOL,
	SHA512,
	HASH_FUNC_COUNT
};

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread char hashOrder[HASH_FUNC_COUNT + 1] = { 0 };

static void getAlgoString(const uint8_t* prevblock, char *output)
{
	char *sptr = output;
	for (int j = 0; j < HASH_FUNC_COUNT; j++) {
		uint8_t b = (15 - j) >> 1; // 16 first ascii hex chars (lsb in uint256)
		uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
		if (algoDigit >= 10)
			sprintf(sptr, "%c", 'A' + (algoDigit - 10));
		else
			sprintf(sptr, "%u", (uint32_t) algoDigit);
		sptr++;
	}
	*sptr = '\0';
}

void x16r_hash(void* output, const void* input)
{
	uint32_t _ALIGN(128) hash[64/4];

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_luffa512_context     ctx_luffa1;
	sph_cubehash512_context  ctx_cubehash1;
	sph_shavite512_context   ctx_shavite1;
	sph_simd512_context      ctx_simd1;
	sph_echo512_context      ctx_echo1;
	sph_hamsi512_context     ctx_hamsi1;
	sph_fugue512_context     ctx_fugue1;
	sph_shabal512_context    ctx_shabal1;
	sph_whirlpool_context    ctx_whirlpool1;
	sph_sha512_context       ctx_sha512;

	void *in = (void*) input;
	int size = 80;

	if (s_ntime == UINT32_MAX) {
		const uint8_t* in8 = (uint8_t*) input;
		getAlgoString(&in8[4], hashOrder);
	}

	for (int i = 0; i < 16; i++)
	{
		const char elem = hashOrder[i];
		const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

		switch (algo) {
		case BLAKE:
			sph_blake512_init(&ctx_blake);
			sph_blake512(&ctx_blake, in, size);
			sph_blake512_close(&ctx_blake, hash);
			break;
		case BMW:
			sph_bmw512_init(&ctx_bmw);
			sph_bmw512(&ctx_bmw, in, size);
			sph_bmw512_close(&ctx_bmw, hash);
			break;
		case GROESTL:
			sph_groestl512_init(&ctx_groestl);
			sph_groestl512(&ctx_groestl, in, size);
			sph_groestl512_close(&ctx_groestl, hash);
			break;
		case SKEIN:
			sph_skein512_init(&ctx_skein);
			sph_skein512(&ctx_skein, in, size);
			sph_skein512_close(&ctx_skein, hash);
			break;
		case JH:
			sph_jh512_init(&ctx_jh);
			sph_jh512(&ctx_jh, in, size);
			sph_jh512_close(&ctx_jh, hash);
			break;
		case KECCAK:
			sph_keccak512_init(&ctx_keccak);
			sph_keccak512(&ctx_keccak, in, size);
			sph_keccak512_close(&ctx_keccak, hash);
			break;
		case LUFFA:
			sph_luffa512_init(&ctx_luffa1);
			sph_luffa512(&ctx_luffa1, in, size);
			sph_luffa512_close(&ctx_luffa1, hash);
			break;
		case CUBEHASH:
			sph_cubehash512_init(&ctx_cubehash1);
			sph_cubehash512(&ctx_cubehash1, in, size);
			sph_cubehash512_close(&ctx_cubehash1, hash);
			break;
		case SHAVITE:
			sph_shavite512_init(&ctx_shavite1);
			sph_shavite512(&ctx_shavite1, in, size);
			sph_shavite512_close(&ctx_shavite1, hash);
			break;
		case SIMD:
			sph_simd512_init(&ctx_simd1);
			sph_simd512(&ctx_simd1, in, size);
			sph_simd512_close(&ctx_simd1, hash);
			break;
		case ECHO:
			sph_echo512_init(&ctx_echo1);
			sph_echo512(&ctx_echo1, in, size);
			sph_echo512_close(&ctx_echo1, hash);
			break;
		case HAMSI:
			sph_hamsi512_init(&ctx_hamsi1);
			sph_hamsi512(&ctx_hamsi1, in, size);
			sph_hamsi512_close(&ctx_hamsi1, hash);
			break;
		case FUGUE:
			sph_fugue512_init(&ctx_fugue1);
			sph_fugue512(&ctx_fugue1, in, size);
			sph_fugue512_close(&ctx_fugue1, hash);
			break;
		case SHABAL:
			sph_shabal512_init(&ctx_shabal1);
			sph_shabal512(&ctx_shabal1, in, size);
			sph_shabal512_close(&ctx_shabal1, hash);
			break;
		case WHIRLPOOL:
			sph_whirlpool_init(&ctx_whirlpool1);
			sph_whirlpool(&ctx_whirlpool1, in, size);
			sph_whirlpool_close(&ctx_whirlpool1, hash);
			break;
		case SHA512:
			sph_sha512_init(&ctx_sha512);
			sph_sha512(&ctx_sha512,(const void*) in, size);
			sph_sha512_close(&ctx_sha512,(void*) hash);
			break;
		}
		in = (void*) hash;
		size = 64;
	}
	memcpy(output, hash, 32);
}

int scanhash_x16r(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	if (s_ntime != pdata[17]) {
		uint32_t ntime = swab32(pdata[17]);
		getAlgoString((const char*) (&endiandata[1]), hashOrder);
		s_ntime = ntime;
		if (opt_debug && !thr_id) applog(LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime);
	}

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	do {
		be32enc(&endiandata[19], nonce);
		x16r_hash(hash32, endiandata);

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
