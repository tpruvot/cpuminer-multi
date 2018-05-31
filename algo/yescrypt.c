#include "miner.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "yescrypt/yescrypt.h"

int do_scanhash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, void (*hash_func)(const char *, char *, uint32_t))
{
	uint32_t _ALIGN(64) vhash[8];
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
		hash_func((char*) endiandata, (char*) vhash, 80);
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio(work, vhash);
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

int scanhash_yescrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	return (do_scanhash(thr_id, work, max_nonce, hashes_done, yescrypt_hash));
}

int scanhash_yescryptr8(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	return (do_scanhash(thr_id, work, max_nonce, hashes_done, yescrypt_hash_r8));
}

int scanhash_yescryptr16(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	return (do_scanhash(thr_id, work, max_nonce, hashes_done, yescrypt_hash_r16));
}

int scanhash_yescryptr32(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	return (do_scanhash(thr_id, work, max_nonce, hashes_done, yescrypt_hash_r32));
}
