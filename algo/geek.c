#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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
#include <sha3/sph_haval.h>

//#define DEBUG_ALGO

void geekhash(void *output, const void *input)
{
	sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;    
    sph_keccak512_context    ctx_keccak;    
    sph_cubehash512_context	ctx_cubehash1;      
    sph_echo512_context		ctx_echo1;
    sph_shabal512_context       ctx_shabal1;
    sph_simd512_context		ctx_simd1;
    sph_hamsi512_context	ctx_hamsi1;


    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_echo512_init (&ctx_echo1); 
    sph_echo512 (&ctx_echo1, hashB, 64);   
    sph_echo512_close(&ctx_echo1, hashA); 

    sph_shabal512_init (&ctx_shabal1);
    sph_shabal512 (&ctx_shabal1, hashA, 64);
    sph_shabal512_close(&ctx_shabal1, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_cubehash512_init (&ctx_cubehash1); 
    sph_cubehash512 (&ctx_cubehash1, hashA, 64);   
    sph_cubehash512_close(&ctx_cubehash1, hashB);    
	
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 64);
    sph_keccak512_close(&ctx_keccak, hashA);

    sph_hamsi512_init (&ctx_hamsi1);
    sph_hamsi512 (&ctx_hamsi1, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi1, hashB);    

    sph_simd512_init (&ctx_simd1); 
    sph_simd512 (&ctx_simd1, hashB, 64);   
    sph_simd512_close(&ctx_simd1, hashA); 

    memcpy(output, hashA, 32);
}

int scanhash_geek(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
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
		geekhash(hash, endiandata);

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
