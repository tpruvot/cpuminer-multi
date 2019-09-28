// RainForest hash algorithm
// Author: Bill Schneider
// Created: Feb 13th, 2018
// Updated: Apr 21th, 2019
//
// RainForest uses native integer operations which are extremely fast on
// modern 64-bit processors, significantly slower on 32-bit processors such
// as GPUs, and extremely slow if at all implementable on FPGAs and ASICs.
// It makes an intensive use of the L1 cache to maintain a heavy intermediary
// state favoring modern CPUs compared to GPUs (small L1 cache shared by many
// shaders) or FPGAs (very hard to implement the required low-latency cache)
// when scanning ranges for nonces. In addition it exploit the perfectly
// defined precision loss of IEEE754 floating point conversion between int and
// double to make sure the implementation runs on a perfectly compliant stack
// and not on a simplified one like an inexpensive IP block. It also uses some
// floating point functions such as sin(), pow() and sqrt() which are available
// on any GPU but could be wrong if simplified. Finally, it uses 96 MB of work
// area per thread in order to incur a cost to highly parallel processors such
// as high-end GPUs. The purpose is to create a fair balance between all mining
// equipments, from mobile phones to extreme performance GPUs and to rule out
// farming factories relying on ASICs, FPGAs, or any other very expensive
// solution. The CRC32 instruction is used a lot as it is extremely fast on
// low-power ARM chips and allows such devices to rival high-end PCs mining
// performance. Note that CRC32 is not used for security at all, only to
// disturb data.
//
// Tests have shown that mid-range OpenCL GPUs can get the computation right
// but that low-end ones not implementing 64-bit floats in hardware and
// falling back to a simplified software stack can't get it right. It was
// also reported that building this code with -ffast-math results in invalid
// hashes, as predicted.
//
// Build instructions on Ubuntu 16.04 to 18.04 :
//   - on x86:   use gcc -lm -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -lm -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.
//
// Note: always use the same options to build all files!
//

#ifndef RAINFOREST
#define RAINFOREST

#include <stdint.h>
#include <stddef.h>

#define RFV2_RAMBOX_SIZE (96*1024*1024/8)

int rfv2_hash(void *out, const void *in, size_t len, void *rambox, const void *rambox_template);
int rfv2_hash2(void *out, const void *in, size_t len, void *rambox, const void *rambox_template, uint32_t seed);
void rfv2_raminit(void *area);

#endif
