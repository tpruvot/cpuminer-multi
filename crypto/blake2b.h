#pragma once
#ifndef __BLAKE2B_H__
#define __BLAKE2B_H__

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <inttypes.h>
#define inline __inline
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

// state context
ALIGN(64) typedef struct {
	uint8_t b[128]; // input buffer
	uint64_t h[8];  // chained state
	uint64_t t[2];  // total number of bytes
	size_t c;       // pointer for b[]
	size_t outlen;  // digest size
} blake2b_ctx;

#if defined(__cplusplus)
extern "C" {
#endif

int blake2b_init(blake2b_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void blake2b_update(blake2b_ctx *ctx, const void *in, size_t inlen);
void blake2b_final(blake2b_ctx *ctx, void *out);

#if defined(__cplusplus)
}
#endif

#endif
