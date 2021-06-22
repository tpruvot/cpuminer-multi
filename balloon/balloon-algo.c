#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "balloon.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#ifdef __cplusplus
extern "C"{
#endif

static void balloon_init (struct balloon_options *opts, int64_t s_cost, int32_t t_cost) {
  opts->s_cost = s_cost;
  opts->t_cost = t_cost;
}

void balloon_128 (unsigned char *input, unsigned char *output) {
  balloon (input, output, 80, 128, 4);
}

void balloon_hash (unsigned char *input, unsigned char *output, int64_t s_cost, int32_t t_cost) {
  balloon (input, output, 80, s_cost, t_cost);
}

void balloon (unsigned char *input, unsigned char *output, int32_t len, int64_t s_cost, int32_t t_cost) {
  struct balloon_options opts;
  struct hash_state s;
  balloon_init (&opts, s_cost, t_cost);
  hash_state_init (&s, &opts, input);
  hash_state_fill (&s, input, input, len);
  hash_state_mix (&s, t_cost);
  hash_state_extract (&s, output);
  hash_state_free (&s);
}

int bitstream_init (struct bitstream *b) {
  SHA256_Init(&b->c);
  b->initialized = false;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  b->ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(b->ctx);
#else
  EVP_CIPHER_CTX_init (&b->ctx);
#endif
  b->zeros = malloc (BITSTREAM_BUF_SIZE * sizeof (uint8_t));
  memset (b->zeros, 0, BITSTREAM_BUF_SIZE);
}

int bitstream_free (struct bitstream *b) {
  uint8_t out[AES_BLOCK_SIZE];
  int outl;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptFinal (b->ctx, out, &outl);
  EVP_CIPHER_CTX_free(b->ctx);
#else
  EVP_EncryptFinal (&b->ctx, out, &outl);
  EVP_CIPHER_CTX_cleanup (&b->ctx);
#endif
  free (b->zeros);
}

int bitstream_seed_add (struct bitstream *b, const void *seed, size_t seedlen) {
  SHA256_Update(&b->c, seed, seedlen);
}

int bitstream_seed_finalize (struct bitstream *b) {
  uint8_t key_bytes[SHA256_DIGEST_LENGTH];
  SHA256_Final (key_bytes, &b->c);
  uint8_t iv[AES_BLOCK_SIZE];
  memset (iv, 0, AES_BLOCK_SIZE);
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_set_padding (b->ctx, 1);
  EVP_EncryptInit (b->ctx, EVP_aes_128_ctr (), key_bytes, iv);
#else
  EVP_CIPHER_CTX_set_padding (&b->ctx, 1);
  EVP_EncryptInit (&b->ctx, EVP_aes_128_ctr (), key_bytes, iv);
#endif
  b->initialized = true;
}

static int encrypt_partial (struct bitstream *b, void *outp, int to_encrypt) {
  int encl;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptUpdate (b->ctx, outp, &encl, b->zeros, to_encrypt);
#else
  EVP_EncryptUpdate (&b->ctx, outp, &encl, b->zeros, to_encrypt);
#endif
}

int bitstream_fill_buffer (struct bitstream *b, void *out, size_t outlen) {
  size_t total = 0;
  while (total < outlen) {
    const int to_encrypt = MIN(outlen - total, BITSTREAM_BUF_SIZE);
    encrypt_partial (b, (char *)out + total, to_encrypt);
    total += to_encrypt;
  }
}

int compress (uint64_t *counter, uint8_t *out, const uint8_t *blocks[], size_t blocks_to_comp) {
  SHA256_CTX ctx;
  SHA256_Init (&ctx);
  SHA256_Update (&ctx, counter, 8);
  for (unsigned int i = 0; i < blocks_to_comp; i++)
    SHA256_Update (&ctx, blocks[i], BLOCK_SIZE);
  SHA256_Final (out, &ctx);
  *counter += 1;
}

int expand (uint64_t *counter, uint8_t *buf, size_t blocks_in_buf) {
  const uint8_t *blocks[1] = { buf };
  uint8_t *cur = buf + BLOCK_SIZE;
  for (size_t i = 1; i < blocks_in_buf; i++) { 
    compress (counter, cur, blocks, 1);
    blocks[0] += BLOCK_SIZE;
    cur += BLOCK_SIZE;
  }
}

uint64_t bytes_to_littleend_uint64 (const uint8_t *bytes, size_t n_bytes) {
  if (n_bytes > 8) 
    n_bytes = 8;
  uint64_t out = 0;
  for (int i = n_bytes-1; i >= 0; i--) {
    out <<= 8;
    out |= bytes[i];
  }
  return out;
}
static __inline void bytes_to_littleend8_uint64 (const uint8_t *bytes, uint64_t *out) {
	*out <<= 8;
	*out |= *(bytes + 7);
	*out <<= 8;
	*out |= *(bytes + 6);
	*out <<= 8;
	*out |= *(bytes + 5);
	*out <<= 8;
	*out |= *(bytes + 4);
	*out <<= 8;
	*out |= *(bytes + 3);
	*out <<= 8;
	*out |= *(bytes + 2);
	*out <<= 8;
	*out |= *(bytes + 1);
	*out <<= 8;
	*out |= *(bytes + 0);
}

void * block_index (const struct hash_state *s, size_t i) {
  return s->buffer + (BLOCK_SIZE * i);
}

static uint64_t options_n_blocks (const struct balloon_options *opts) {
  const uint32_t bsize = BLOCK_SIZE;
  uint64_t ret = (opts->s_cost * 1024) / bsize;
  return (ret < BLOCKS_MIN) ? BLOCKS_MIN : ret;
}

void * block_last (const struct hash_state *s) {
  return block_index (s, s->n_blocks - 1);
}

int hash_state_init (struct hash_state *s, const struct balloon_options *opts, const uint8_t salt[SALT_LEN]) {
  s->counter = 0;
  s->n_blocks = options_n_blocks (opts);
  if (s->n_blocks % 2 != 0) s->n_blocks++;
  s->has_mixed = false;
  s->opts = opts;
  s->buffer = malloc (s->n_blocks * BLOCK_SIZE);
  int a = salt[0];
  a++;
  bitstream_init (&s->bstream);
  bitstream_seed_add (&s->bstream, salt, SALT_LEN);
  bitstream_seed_add (&s->bstream, &opts->s_cost, 8);
  bitstream_seed_add (&s->bstream, &opts->t_cost, 4);
  bitstream_seed_finalize (&s->bstream);
}

int hash_state_free (struct hash_state *s) {
  bitstream_free (&s->bstream);
  free (s->buffer);
}

int hash_state_fill (struct hash_state *s, const uint8_t salt[SALT_LEN], const uint8_t *in, size_t inlen) {
  SHA256_CTX c;
  SHA256_Init (&c);
  SHA256_Update (&c, &s->counter, 8);
  SHA256_Update (&c, salt, SALT_LEN);
  SHA256_Update (&c, in, inlen);
  SHA256_Update (&c, &s->opts->s_cost, 8);
  SHA256_Update (&c, &s->opts->t_cost, 4);
  SHA256_Final (s->buffer, &c);
  s->counter++;
  expand (&s->counter, s->buffer, s->n_blocks);
}

uint8_t prebuf[409600];
uint64_t prebuf_le[409600 / 8];
uint8_t prebuf_filled = 0;
int hash_state_mix (struct hash_state *s, int32_t mixrounds) {
	if (!prebuf_filled) {
		bitstream_fill_buffer (&s->bstream, prebuf, 409600);
		prebuf_filled = 1;
		uint8_t *buf = prebuf;
		uint64_t *lebuf = prebuf_le;
		for (int i = 0; i < 409600; i+=8) {
			bytes_to_littleend8_uint64(buf, lebuf);
			*lebuf %= 4096;
			lebuf++;
			buf += 8;
		}
	}
	uint64_t *buf = prebuf_le;
	uint8_t *sbuf = s->buffer;

	uint64_t neighbor;
	int32_t n_blocks = s->n_blocks;
	uint8_t *last_block = (sbuf + (BLOCK_SIZE*(n_blocks-1)));
	for (int32_t rounds=0; rounds < mixrounds; rounds++) {
		uint8_t *cur_block = sbuf;
		const uint8_t *blocks[5];
		uint8_t **block = blocks;
		{ // i = 0
			*(block++) = last_block;
			*(block++) = cur_block;
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));

			compress (&s->counter, cur_block, blocks, 5);
			cur_block += BLOCK_SIZE;
		}
		for (size_t i = 1; i < n_blocks; i++) {
			block = blocks;
			*(block++) = cur_block - BLOCK_SIZE;
			*(block++) = cur_block;
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));
			*(block++) = (sbuf + (BLOCK_SIZE * (*(buf++))));

			compress (&s->counter, cur_block, blocks, 5);
			cur_block += BLOCK_SIZE;
		}
		s->has_mixed = true;
	}
}

int hash_state_extract (const struct hash_state *s, uint8_t out[BLOCK_SIZE]) {
  uint8_t *b = block_last (s);
  memcpy ((char *)out, (const char *)b, BLOCK_SIZE);
}

void balloon_reset() {
	prebuf_filled = 0;
}

#ifdef __cplusplus
}
#endif
