/*
 * HEFTY1 cryptographic hash function
 *
 * Copyright (c) 2014, dbcc14 <BM-NBx4AKznJuyem3dArgVY8MGyABpihRy5>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */

#include <assert.h>
#include <string.h>

#ifdef _MSC_VER
#define inline __inline
#endif

#include "sph_hefty1.h"

#define Min(A, B) (A <= B ? A : B)
#define RoundFunc(ctx, A, B, C, D, E, F, G, H, W, K)                    \
    {                                                                   \
        /* To thwart parallelism, Br modifies itself each time it's     \
         * called.  This also means that calling it in different        \
         * orders yeilds different results.  In C the order of          \
         * evaluation of function arguments and + operands are          \
         * unspecified (and depends on the compiler), so we must make   \
         * the order of Br calls explicit.                              \
         */                                                             \
        uint32_t brG = Br(ctx, G);                                      \
        uint32_t tmp1 = Ch(E, Br(ctx, F), brG) + H + W + K;             \
        uint32_t tmp2 = tmp1 + Sigma1(Br(ctx, E));                      \
        uint32_t brC = Br(ctx, C);                                      \
        uint32_t brB = Br(ctx, B);                                      \
        uint32_t tmp3 = Ma(Br(ctx, A), brB, brC);                       \
        uint32_t tmp4 = tmp3 + Sigma0(Br(ctx, A));                      \
        H = G;                                                          \
        G = F;                                                          \
        F = E;                                                          \
        E = D + Br(ctx, tmp2);                                          \
        D = C;                                                          \
        C = B;                                                          \
        B = A;                                                          \
        A = tmp2 + tmp4;                                                \
    }                                                                   \

/* Nothing up my sleeve constants */
const static uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Initial hash values */
const static uint32_t H[HEFTY1_STATE_WORDS] = {
    0x6a09e667UL,
    0xbb67ae85UL,
    0x3c6ef372UL,
    0xa54ff53aUL,
    0x510e527fUL,
    0x9b05688cUL,
    0x1f83d9abUL,
    0x5be0cd19UL
};

static inline uint32_t Rr(uint32_t X, uint8_t n)
{
    return (X >> n) | (X << (32 - n));
}

static inline uint32_t Ch(uint32_t E, uint32_t F, uint32_t G)
{
    return (E & F) ^ (~E & G);
}

static inline uint32_t Sigma1(uint32_t E)
{
    return Rr(E, 6) ^ Rr(E, 11) ^ Rr(E, 25);
}

static inline uint32_t sigma1(uint32_t X)
{
    return Rr(X, 17) ^ Rr(X, 19) ^ (X >> 10);
}

static inline uint32_t Ma(uint32_t A, uint32_t B, uint32_t C)
{
    return (A & B) ^ (A & C) ^ (B & C);
}

static inline uint32_t Sigma0(uint32_t A)
{
    return Rr(A, 2) ^ Rr(A, 13) ^ Rr(A, 22);
}

static inline uint32_t sigma0(uint32_t X)
{
    return Rr(X, 7) ^ Rr(X, 18) ^ (X >> 3);
}

static inline uint32_t Reverse32(uint32_t n)
{
    #if BYTE_ORDER == LITTLE_ENDIAN
        return n << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | n >> 24;
    #else
        return n;
    #endif
}

static inline uint64_t Reverse64(uint64_t n)
{
    #if BYTE_ORDER == LITTLE_ENDIAN
        uint32_t a = n >> 32;
        uint32_t b = (n << 32) >> 32;

        return (uint64_t)Reverse32(b) << 32 | Reverse32(a);
    #else
        return n;
    #endif
}

/* Smoosh byte into nibble */
static inline uint8_t Smoosh4(uint8_t X)
{
    return (X >> 4) ^ (X & 0xf);
}

/* Smoosh 32-bit word into 2-bits */
static inline uint8_t Smoosh2(uint32_t X)
{
    uint16_t w = (X >> 16) ^ (X & 0xffff);
    uint8_t n = Smoosh4((w >> 8) ^ (w & 0xff));
    return (n >> 2) ^ (n & 0x3);
}

static void Mangle(uint32_t *S)
{
    uint32_t *R = S;
    uint32_t *C = &S[1];

    uint8_t r0 = Smoosh4(R[0] >> 24);
    uint8_t r1 = Smoosh4(R[0] >> 16);
    uint8_t r2 = Smoosh4(R[0] >> 8);
    uint8_t r3 = Smoosh4(R[0] & 0xff);

    int i;

    /* Diffuse */
    uint32_t tmp = 0;
    for (i = 0; i < HEFTY1_SPONGE_WORDS - 1; i++) {
        uint8_t r = Smoosh2(tmp);
        switch (r) {
        case 0:
            C[i] ^= Rr(R[0], i + r0);
            break;
        case 1:
            C[i] += Rr(~R[0], i + r1);
            break;
        case 2:
            C[i] &= Rr(~R[0], i + r2);
            break;
        case 3:
            C[i] ^= Rr(R[0], i + r3);
            break;
        }
        tmp ^= C[i];
    }

    /* Compress */
    tmp = 0;
    for (i = 0; i < HEFTY1_SPONGE_WORDS - 1; i++)
        if (i % 2)
            tmp ^= C[i];
        else
            tmp += C[i];
    R[0] ^= tmp;
}

static void Absorb(uint32_t *S, uint32_t X)
{
    uint32_t *R = S;
    R[0] ^= X;
    Mangle(S);
}

static uint32_t Squeeze(uint32_t *S)
{
    uint32_t Y = S[0];
    Mangle(S);
    return Y;
}

/* Branch, compress and serialize function */
static inline uint32_t Br(HEFTY1_CTX *ctx, uint32_t X)
{
    uint32_t R = Squeeze(ctx->sponge);

    uint8_t r0 = R >> 8;
    uint8_t r1 = R & 0xff;

    uint32_t Y = 1 << (r0 % 32);

    switch (r1 % 4)
    {
    case 0:
        /* Do nothing */
        break;
    case 1:
        return X & ~Y;
    case 2:
        return X | Y;
    case 3:
        return X ^ Y;
    }

    return X;
}

static void HashBlock(HEFTY1_CTX *ctx)
{
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t W[HEFTY1_BLOCK_BYTES];

    assert(ctx);

    A = ctx->h[0];
    B = ctx->h[1];
    C = ctx->h[2];
    D = ctx->h[3];
    E = ctx->h[4];
    F = ctx->h[5];
    G = ctx->h[6];
    H = ctx->h[7];

    int t = 0;
    for (; t < 16; t++) {
        W[t] = Reverse32(((uint32_t *)&ctx->block[0])[t]); /* To host byte order */
        Absorb(ctx->sponge, W[t] ^ K[t]);
    }

    for (t = 0; t < 16; t++) {
        Absorb(ctx->sponge, D ^ H);
        RoundFunc(ctx, A, B, C, D, E, F, G, H, W[t], K[t]);
    }
    for (t = 16; t < 64; t++) {
        Absorb(ctx->sponge, H + D);
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        RoundFunc(ctx, A, B, C, D, E, F, G, H, W[t], K[t]);
    }

    ctx->h[0] += A;
    ctx->h[1] += B;
    ctx->h[2] += C;
    ctx->h[3] += D;
    ctx->h[4] += E;
    ctx->h[5] += F;
    ctx->h[6] += G;
    ctx->h[7] += H;

    A = 0;
    B = 0;
    C = 0;
    D = 0;
    E = 0;
    F = 0;
    G = 0;
    H = 0;

    memset(W, 0, sizeof(W));
}

/* Public interface */

void HEFTY1_Init(HEFTY1_CTX *ctx)
{
    assert(ctx);

    memcpy(ctx->h, H, sizeof(ctx->h));
    memset(ctx->block, 0, sizeof(ctx->block));
    ctx->written = 0;
    memset(ctx->sponge, 0, sizeof(ctx->sponge));
}

void HEFTY1_Update(HEFTY1_CTX *ctx, const void *buf, size_t len)
{
    assert(ctx);

    uint64_t read = 0;
    while (len) {
        size_t end = (size_t)(ctx->written % HEFTY1_BLOCK_BYTES);
        size_t count = Min(len, HEFTY1_BLOCK_BYTES - end);
        memcpy(&ctx->block[end], &((unsigned char *)buf)[read], count);
        len -= count;
        read += count;
        ctx->written += count;
        if (!(ctx->written % HEFTY1_BLOCK_BYTES))
            HashBlock(ctx);
    }
}

void HEFTY1_Final(unsigned char *digest, HEFTY1_CTX *ctx)
{
    assert(digest);
    assert(ctx);

    /* Pad message (FIPS 180 Section 5.1.1) */
    size_t used = (size_t)(ctx->written % HEFTY1_BLOCK_BYTES);
    ctx->block[used++] = 0x80; /* Append 1 to end of message */
    if (used > HEFTY1_BLOCK_BYTES - 8) {
        /* We have already written into the last 64bits, so
         * we must continue into the next block. */
        memset(&ctx->block[used], 0, HEFTY1_BLOCK_BYTES - used);
        HashBlock(ctx);
        used = 0; /* Create a new block (below) */
    }

    /* All remaining bits to zero */
    memset(&ctx->block[used], 0, HEFTY1_BLOCK_BYTES - 8 - used);

    /* The last 64bits encode the length (in network byte order) */
    uint64_t *len = (uint64_t *)&ctx->block[HEFTY1_BLOCK_BYTES - 8];
    *len = Reverse64(ctx->written*8);

    HashBlock(ctx);

    /* Convert back to network byte order */
    int i = 0;
    for (; i < HEFTY1_STATE_WORDS; i++)
        ctx->h[i] = Reverse32(ctx->h[i]);

    memcpy(digest, ctx->h, sizeof(ctx->h));
    memset(ctx, 0, sizeof(HEFTY1_CTX));
}

unsigned char* HEFTY1(const unsigned char *buf, size_t len, unsigned char *digest)
{
    HEFTY1_CTX ctx;
    static unsigned char m[HEFTY1_DIGEST_BYTES];

    if (!digest)
        digest = m;

    HEFTY1_Init(&ctx);
    HEFTY1_Update(&ctx, buf, len);
    HEFTY1_Final(digest, &ctx);

    return digest;
}