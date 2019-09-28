// RainForest hash algorithm - cpuminer integration code
// Author: Bill Schneider
// Date: Feb 13th, 2018
//
// Build instructions on Ubuntu 16.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.

#include <miner.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "rfv2_core.c"

int scanhash_rfv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t RF_ALIGN(64) hash[8];
	uint32_t RF_ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	static void *rambox;
	int ret = 0;

	if (opt_benchmark)
		Htarg = ptarget[7] = 0x1ffff;

	//printf("thd%d work=%p htarg=%08x ptarg7=%08x first_nonce=%08x max_nonce=%08x hashes_done=%Lu\n",
	//       thr_id, work, Htarg, ptarget[7], first_nonce, max_nonce, (unsigned long)*hashes_done);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	if (!rambox) {
		//printf("Rambox not yet initialized\n");
		if (!thr_id) {
			/* only thread 0 is responsible for allocating the shared rambox */
			void *r = malloc(RFV2_RAMBOX_SIZE * 8);
			if (r == NULL) {
				//printf("[%d] rambox allocation failed\n", thr_id);
				*(volatile void **)&rambox = (void*)0x1;
				goto out;
			}
			//printf("Thread %d initializing the rambox\n", thr_id);
			rfv2_raminit(r);
			*(volatile void **)&rambox = r;
		} else {
			/* wait for thread 0 to finish alloc+init of rambox */
			//printf("Thread %d waiting for rambox init\n", thr_id);
			while (!*(volatile void **)&rambox)
				usleep(100000);
		}
	}

	if (*(volatile void **)&rambox == (void*)0x1) {
		//printf("[%d] rambox allocation failed\n", thr_id);
		goto out; // the rambox wasn't properly initialized
	}

	do {
		ret = rfv2_scan_hdr((char *)endiandata, rambox, hash, Htarg, nonce, max_nonce, restart);
		nonce = be32toh(endiandata[19]);
		if (ret <= 0)
			break;

		if (fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = ret;
			ret = 1;
			goto out;
		}
		nonce++;
	} while (nonce < max_nonce && !(*restart));

	/* not found */
	pdata[19] = nonce;
	*hashes_done = -ret;
	ret = 0;
out:
	return ret;
}
