/* $Id: sph_radiogatun.h 226 2010-06-16 17:28:08Z tp $ */
/**
 * RadioGatun interface.
 *
 * RadioGatun has been published in: G. Bertoni, J. Daemen, M. Peeters
 * and G. Van Assche, "RadioGatun, a belt-and-mill hash function",
 * presented at the Second Cryptographic Hash Workshop, Santa Barbara,
 * August 24-25, 2006. The main Web site, containing that article, the
 * reference code and some test vectors, appears to be currently located
 * at the following URL: http://radiogatun.noekeon.org/
 *
 * The presentation article does not specify endianness or padding. The
 * reference code uses the following conventions, which we also apply
 * here:
 * <ul>
 * <li>The input message is an integral number of sequences of three
 * words. Each word is either a 32-bit of 64-bit word (depending on
 * the version of RadioGatun).</li>
 * <li>Input bytes are decoded into words using little-endian
 * convention.</li>
 * <li>Padding consists of a single bit of value 1, using little-endian
 * convention within bytes (i.e. for a byte-oriented input, a single
 * byte of value 0x01 is appended), then enough bits of value 0 to finish
 * the current block.</li>
 * <li>Output consists of 256 bits. Successive output words are encoded
 * with little-endian convention.</li>
 * </ul>
 * These conventions are very close to those we use for PANAMA, which is
 * a close ancestor or RadioGatun.
 *
 * RadioGatun is actually a family of functions, depending on some
 * internal parameters. We implement here two functions, with a "belt
 * length" of 13, a "belt width" of 3, and a "mill length" of 19. The
 * RadioGatun[32] version uses 32-bit words, while the RadioGatun[64]
 * variant uses 64-bit words.
 *
 * Strictly speaking, the name "RadioGatun" should use an acute accent
 * on the "u", which we omitted here to keep strict ASCII-compatibility
 * of this file.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_radiogatun.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_RADIOGATUN_H__
#define SPH_RADIOGATUN_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for RadioGatun[32].
 */
#define SPH_SIZE_radiogatun32   256

/**
 * This structure is a context for RadioGatun[32] computations: it
 * contains intermediate values and some data from the last entered
 * block. Once a RadioGatun[32] computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running RadioGatun[32]
 * computation can be cloned by copying the context (e.g. with a
 * simple <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char data[156];   /* first field, for alignment */
	unsigned data_ptr;
	sph_u32 a[19], b[39];
#endif
} sph_radiogatun32_context;

/**
 * Initialize a RadioGatun[32] context. This process performs no
 * memory allocation.
 *
 * @param cc   the RadioGatun[32] context (pointer to a
 *             <code>sph_radiogatun32_context</code>)
 */
void sph_radiogatun32_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RadioGatun[32] context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_radiogatun32(void *cc, const void *data, size_t len);

/**
 * Terminate the current RadioGatun[32] computation and output the
 * result into the provided buffer. The destination buffer must be wide
 * enough to accomodate the result (32 bytes). The context is
 * automatically reinitialized.
 *
 * @param cc    the RadioGatun[32] context
 * @param dst   the destination buffer
 */
void sph_radiogatun32_close(void *cc, void *dst);

#if SPH_64

/**
 * Output size (in bits) for RadioGatun[64].
 */
#define SPH_SIZE_radiogatun64   256

/**
 * This structure is a context for RadioGatun[64] computations: it
 * contains intermediate values and some data from the last entered
 * block. Once a RadioGatun[64] computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running RadioGatun[64]
 * computation can be cloned by copying the context (e.g. with a
 * simple <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char data[312];   /* first field, for alignment */
	unsigned data_ptr;
	sph_u64 a[19], b[39];
#endif
} sph_radiogatun64_context;

/**
 * Initialize a RadioGatun[64] context. This process performs no
 * memory allocation.
 *
 * @param cc   the RadioGatun[64] context (pointer to a
 *             <code>sph_radiogatun64_context</code>)
 */
void sph_radiogatun64_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RadioGatun[64] context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_radiogatun64(void *cc, const void *data, size_t len);

/**
 * Terminate the current RadioGatun[64] computation and output the
 * result into the provided buffer. The destination buffer must be wide
 * enough to accomodate the result (32 bytes). The context is
 * automatically reinitialized.
 *
 * @param cc    the RadioGatun[64] context
 * @param dst   the destination buffer
 */
void sph_radiogatun64_close(void *cc, void *dst);

#endif

#endif