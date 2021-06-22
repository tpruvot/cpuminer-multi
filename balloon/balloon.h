#include <stdbool.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITSTREAM_BUF_SIZE ((32) * (AES_BLOCK_SIZE))
#define N_NEIGHBORS (3)
#define SALT_LEN (32)
#define INLEN_MAX (1ull<<20)
#define TCOST_MIN 1ull
#define SCOST_MIN (1)
#define SCOST_MAX (UINT32_MAX)
#define BLOCKS_MIN (1ull)
#define THREADS_MAX 4096
#define BLOCK_SIZE (32)
#define UNUSED __attribute__ ((unused))

struct bitstream {
  bool initialized;
  uint8_t *zeros;
  SHA256_CTX c;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX* ctx;
#else
  EVP_CIPHER_CTX ctx;
#endif
};

struct hash_state;

struct hash_state {
  uint64_t counter;
  uint64_t n_blocks;
  bool has_mixed;
  uint8_t *buffer;
  struct bitstream bstream;
  const struct balloon_options *opts;
};

struct balloon_options {
  int64_t s_cost;
  int32_t t_cost;
};

void balloon_128 (unsigned char *input, unsigned char *output);
void balloon_hash (unsigned char *input, unsigned char *output, int64_t s_cost, int32_t t_cost);
void balloon (unsigned char *input, unsigned char *output, int32_t len, int64_t s_cost, int32_t t_cost);

int bitstream_init (struct bitstream *b);
int bitstream_free (struct bitstream *b);
int bitstream_seed_add (struct bitstream *b, const void *seed, size_t seedlen);
int bitstream_seed_finalize (struct bitstream *b);
int bitstream_fill_buffer (struct bitstream *b, void *out, size_t outlen);
int bitstream_rand_byte (struct bitstream *b, uint8_t *out);
int compress (uint64_t *counter, uint8_t *out, const uint8_t *blocks[], size_t blocks_to_comp);
int expand (uint64_t *counter, uint8_t *buf, size_t blocks_in_buf);
uint64_t bytes_to_littleend_uint64 (const uint8_t *bytes, size_t n_bytes);
int hash_state_init (struct hash_state *s, const struct balloon_options *opts, const uint8_t salt[SALT_LEN]);
int hash_state_free (struct hash_state *s);
int hash_state_fill (struct hash_state *s, const uint8_t salt[SALT_LEN], const uint8_t *in, size_t inlen);
int hash_state_mix (struct hash_state *s, int32_t mixrounds);
int hash_state_extract (const struct hash_state *s, uint8_t out[BLOCK_SIZE]);
void * block_index (const struct hash_state *s, size_t i); 
void * block_last (const struct hash_state *s);

#ifdef __cplusplus
}
#endif
