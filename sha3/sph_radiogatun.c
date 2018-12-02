/* $Id: radiogatun.c 226 2010-06-16 17:28:08Z tp $ */
/*
 * RadioGatun implementation.
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
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#include "sph_radiogatun.h"

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_RADIOGATUN
#define SPH_SMALL_FOOTPRINT_RADIOGATUN   1
#endif

/* ======================================================================= */
/*
 * The core macros. We want to unroll 13 successive rounds so that the
 * belt rotation becomes pure routing, solved at compilation time, with
 * no unnecessary copying. We also wish all state variables to be
 * independant local variables, so that the C compiler becomes free to
 * map these on registers at it sees fit. This requires some heavy
 * preprocessor trickeries, including a full addition macro modulo 13.
 *
 * These macros are size-independent. Some macros must be defined before
 * use:
 *   WT           evaluates to the type for a word (32-bit or 64-bit)
 *   T            truncates a value to the proper word size
 *   ROR(x, n)    right rotation of a word x, with explicit modular
 *                reduction of the rotation count n by the word size
 *   INW(i, j)    input word j (0, 1, or 2) of block i (0 to 12)
 *
 * For INW, the input buffer is pointed to by "buf" which has type
 * "const unsigned char *".
 */

#define MUL19(action)   do { \
		action(0); \
		action(1); \
		action(2); \
		action(3); \
		action(4); \
		action(5); \
		action(6); \
		action(7); \
		action(8); \
		action(9); \
		action(10); \
		action(11); \
		action(12); \
		action(13); \
		action(14); \
		action(15); \
		action(16); \
		action(17); \
		action(18); \
	} while (0)

#define DECL19(b)   b ## 0, b ## 1, b ## 2, b ## 3, b ## 4, b ## 5, \
                    b ## 6, b ## 7, b ## 8, b ## 9, b ## 10, b ## 11, \
                    b ## 12, b ## 13, b ## 14, b ## 15, b ## 16, \
                    b ## 17, b ## 18

#define M19_T7(i)    M19_T7_(i)
#define M19_T7_(i)   M19_T7_ ## i
#define M19_T7_0     0
#define M19_T7_1     7
#define M19_T7_2     14
#define M19_T7_3     2
#define M19_T7_4     9
#define M19_T7_5     16
#define M19_T7_6     4
#define M19_T7_7     11
#define M19_T7_8     18
#define M19_T7_9     6
#define M19_T7_10    13
#define M19_T7_11    1
#define M19_T7_12    8
#define M19_T7_13    15
#define M19_T7_14    3
#define M19_T7_15    10
#define M19_T7_16    17
#define M19_T7_17    5
#define M19_T7_18    12

#define M19_A1(i)    M19_A1_(i)
#define M19_A1_(i)   M19_A1_ ## i
#define M19_A1_0     1
#define M19_A1_1     2
#define M19_A1_2     3
#define M19_A1_3     4
#define M19_A1_4     5
#define M19_A1_5     6
#define M19_A1_6     7
#define M19_A1_7     8
#define M19_A1_8     9
#define M19_A1_9     10
#define M19_A1_10    11
#define M19_A1_11    12
#define M19_A1_12    13
#define M19_A1_13    14
#define M19_A1_14    15
#define M19_A1_15    16
#define M19_A1_16    17
#define M19_A1_17    18
#define M19_A1_18    0

#define M19_A2(i)    M19_A2_(i)
#define M19_A2_(i)   M19_A2_ ## i
#define M19_A2_0     2
#define M19_A2_1     3
#define M19_A2_2     4
#define M19_A2_3     5
#define M19_A2_4     6
#define M19_A2_5     7
#define M19_A2_6     8
#define M19_A2_7     9
#define M19_A2_8     10
#define M19_A2_9     11
#define M19_A2_10    12
#define M19_A2_11    13
#define M19_A2_12    14
#define M19_A2_13    15
#define M19_A2_14    16
#define M19_A2_15    17
#define M19_A2_16    18
#define M19_A2_17    0
#define M19_A2_18    1

#define M19_A4(i)    M19_A4_(i)
#define M19_A4_(i)   M19_A4_ ## i
#define M19_A4_0     4
#define M19_A4_1     5
#define M19_A4_2     6
#define M19_A4_3     7
#define M19_A4_4     8
#define M19_A4_5     9
#define M19_A4_6     10
#define M19_A4_7     11
#define M19_A4_8     12
#define M19_A4_9     13
#define M19_A4_10    14
#define M19_A4_11    15
#define M19_A4_12    16
#define M19_A4_13    17
#define M19_A4_14    18
#define M19_A4_15    0
#define M19_A4_16    1
#define M19_A4_17    2
#define M19_A4_18    3

#define ACC_a(i)    ACC_a_(i)
#define ACC_a_(i)   a ## i
#define ACC_atmp(i)    ACC_atmp_(i)
#define ACC_atmp_(i)   atmp ## i

#define MILL1(i)   (atmp ## i = a ## i ^ T(ACC_a(M19_A1(i)) \
                   | ~ACC_a(M19_A2(i))))
#define MILL2(i)   (a ## i = ROR(ACC_atmp(M19_T7(i)), ((i * (i + 1)) >> 1)))
#define MILL3(i)   (atmp ## i = a ## i ^ ACC_a(M19_A1(i)) ^ ACC_a(M19_A4(i)))
#define MILL4(i)   (a ## i = atmp ## i ^ (i == 0))

#define MILL   do { \
		WT DECL19(atmp); \
		MUL19(MILL1); \
		MUL19(MILL2); \
		MUL19(MILL3); \
		MUL19(MILL4); \
	} while (0)

#define DECL13(b)   b ## 0 ## _0, b ## 0 ## _1, b ## 0 ## _2, \
                    b ## 1 ## _0, b ## 1 ## _1, b ## 1 ## _2, \
                    b ## 2 ## _0, b ## 2 ## _1, b ## 2 ## _2, \
                    b ## 3 ## _0, b ## 3 ## _1, b ## 3 ## _2, \
                    b ## 4 ## _0, b ## 4 ## _1, b ## 4 ## _2, \
                    b ## 5 ## _0, b ## 5 ## _1, b ## 5 ## _2, \
                    b ## 6 ## _0, b ## 6 ## _1, b ## 6 ## _2, \
                    b ## 7 ## _0, b ## 7 ## _1, b ## 7 ## _2, \
                    b ## 8 ## _0, b ## 8 ## _1, b ## 8 ## _2, \
                    b ## 9 ## _0, b ## 9 ## _1, b ## 9 ## _2, \
                    b ## 10 ## _0, b ## 10 ## _1, b ## 10 ## _2, \
                    b ## 11 ## _0, b ## 11 ## _1, b ## 11 ## _2, \
                    b ## 12 ## _0, b ## 12 ## _1, b ## 12 ## _2

#define M13_A(i, j)    M13_A_(i, j)
#define M13_A_(i, j)   M13_A_ ## i ## _ ## j
#define M13_A_0_0      0
#define M13_A_0_1      1
#define M13_A_0_2      2
#define M13_A_0_3      3
#define M13_A_0_4      4
#define M13_A_0_5      5
#define M13_A_0_6      6
#define M13_A_0_7      7
#define M13_A_0_8      8
#define M13_A_0_9      9
#define M13_A_0_10     10
#define M13_A_0_11     11
#define M13_A_0_12     12
#define M13_A_1_0      1
#define M13_A_1_1      2
#define M13_A_1_2      3
#define M13_A_1_3      4
#define M13_A_1_4      5
#define M13_A_1_5      6
#define M13_A_1_6      7
#define M13_A_1_7      8
#define M13_A_1_8      9
#define M13_A_1_9      10
#define M13_A_1_10     11
#define M13_A_1_11     12
#define M13_A_1_12     0
#define M13_A_2_0      2
#define M13_A_2_1      3
#define M13_A_2_2      4
#define M13_A_2_3      5
#define M13_A_2_4      6
#define M13_A_2_5      7
#define M13_A_2_6      8
#define M13_A_2_7      9
#define M13_A_2_8      10
#define M13_A_2_9      11
#define M13_A_2_10     12
#define M13_A_2_11     0
#define M13_A_2_12     1
#define M13_A_3_0      3
#define M13_A_3_1      4
#define M13_A_3_2      5
#define M13_A_3_3      6
#define M13_A_3_4      7
#define M13_A_3_5      8
#define M13_A_3_6      9
#define M13_A_3_7      10
#define M13_A_3_8      11
#define M13_A_3_9      12
#define M13_A_3_10     0
#define M13_A_3_11     1
#define M13_A_3_12     2
#define M13_A_4_0      4
#define M13_A_4_1      5
#define M13_A_4_2      6
#define M13_A_4_3      7
#define M13_A_4_4      8
#define M13_A_4_5      9
#define M13_A_4_6      10
#define M13_A_4_7      11
#define M13_A_4_8      12
#define M13_A_4_9      0
#define M13_A_4_10     1
#define M13_A_4_11     2
#define M13_A_4_12     3
#define M13_A_5_0      5
#define M13_A_5_1      6
#define M13_A_5_2      7
#define M13_A_5_3      8
#define M13_A_5_4      9
#define M13_A_5_5      10
#define M13_A_5_6      11
#define M13_A_5_7      12
#define M13_A_5_8      0
#define M13_A_5_9      1
#define M13_A_5_10     2
#define M13_A_5_11     3
#define M13_A_5_12     4
#define M13_A_6_0      6
#define M13_A_6_1      7
#define M13_A_6_2      8
#define M13_A_6_3      9
#define M13_A_6_4      10
#define M13_A_6_5      11
#define M13_A_6_6      12
#define M13_A_6_7      0
#define M13_A_6_8      1
#define M13_A_6_9      2
#define M13_A_6_10     3
#define M13_A_6_11     4
#define M13_A_6_12     5
#define M13_A_7_0      7
#define M13_A_7_1      8
#define M13_A_7_2      9
#define M13_A_7_3      10
#define M13_A_7_4      11
#define M13_A_7_5      12
#define M13_A_7_6      0
#define M13_A_7_7      1
#define M13_A_7_8      2
#define M13_A_7_9      3
#define M13_A_7_10     4
#define M13_A_7_11     5
#define M13_A_7_12     6
#define M13_A_8_0      8
#define M13_A_8_1      9
#define M13_A_8_2      10
#define M13_A_8_3      11
#define M13_A_8_4      12
#define M13_A_8_5      0
#define M13_A_8_6      1
#define M13_A_8_7      2
#define M13_A_8_8      3
#define M13_A_8_9      4
#define M13_A_8_10     5
#define M13_A_8_11     6
#define M13_A_8_12     7
#define M13_A_9_0      9
#define M13_A_9_1      10
#define M13_A_9_2      11
#define M13_A_9_3      12
#define M13_A_9_4      0
#define M13_A_9_5      1
#define M13_A_9_6      2
#define M13_A_9_7      3
#define M13_A_9_8      4
#define M13_A_9_9      5
#define M13_A_9_10     6
#define M13_A_9_11     7
#define M13_A_9_12     8
#define M13_A_10_0     10
#define M13_A_10_1     11
#define M13_A_10_2     12
#define M13_A_10_3     0
#define M13_A_10_4     1
#define M13_A_10_5     2
#define M13_A_10_6     3
#define M13_A_10_7     4
#define M13_A_10_8     5
#define M13_A_10_9     6
#define M13_A_10_10    7
#define M13_A_10_11    8
#define M13_A_10_12    9
#define M13_A_11_0     11
#define M13_A_11_1     12
#define M13_A_11_2     0
#define M13_A_11_3     1
#define M13_A_11_4     2
#define M13_A_11_5     3
#define M13_A_11_6     4
#define M13_A_11_7     5
#define M13_A_11_8     6
#define M13_A_11_9     7
#define M13_A_11_10    8
#define M13_A_11_11    9
#define M13_A_11_12    10
#define M13_A_12_0     12
#define M13_A_12_1     0
#define M13_A_12_2     1
#define M13_A_12_3     2
#define M13_A_12_4     3
#define M13_A_12_5     4
#define M13_A_12_6     5
#define M13_A_12_7     6
#define M13_A_12_8     7
#define M13_A_12_9     8
#define M13_A_12_10    9
#define M13_A_12_11    10
#define M13_A_12_12    11

#define M13_N(i)    M13_N_(i)
#define M13_N_(i)   M13_N_ ## i
#define M13_N_0     12
#define M13_N_1     11
#define M13_N_2     10
#define M13_N_3     9
#define M13_N_4     8
#define M13_N_5     7
#define M13_N_6     6
#define M13_N_7     5
#define M13_N_8     4
#define M13_N_9     3
#define M13_N_10    2
#define M13_N_11    1
#define M13_N_12    0

#define ACC_b(i, k)    ACC_b_(i, k)
#define ACC_b_(i, k)   b ## i ## _ ## k

#define ROUND_ELT(k, s)   do { \
		if ((bj += 3) == 39) \
			bj = 0; \
		sc->b[bj + s] ^= a ## k; \
	} while (0)

#define ROUND_SF(j)   do { \
		size_t bj = (j) * 3; \
		ROUND_ELT(1, 0); \
		ROUND_ELT(2, 1); \
		ROUND_ELT(3, 2); \
		ROUND_ELT(4, 0); \
		ROUND_ELT(5, 1); \
		ROUND_ELT(6, 2); \
		ROUND_ELT(7, 0); \
		ROUND_ELT(8, 1); \
		ROUND_ELT(9, 2); \
		ROUND_ELT(10, 0); \
		ROUND_ELT(11, 1); \
		ROUND_ELT(12, 2); \
		MILL; \
		bj = (j) * 3; \
		a ## 13 ^= sc->b[bj + 0]; \
		a ## 14 ^= sc->b[bj + 1]; \
		a ## 15 ^= sc->b[bj + 2]; \
	} while (0)

#define INPUT_SF(j, p0, p1, p2)   do { \
		size_t bj = ((j) + 1) * 3; \
		if (bj == 39) \
			bj = 0; \
		sc->b[bj + 0] ^= (p0); \
		sc->b[bj + 1] ^= (p1); \
		sc->b[bj + 2] ^= (p2); \
		a16 ^= (p0); \
		a17 ^= (p1); \
		a18 ^= (p2); \
	} while (0)


#if SPH_SMALL_FOOTPRINT_RADIOGATUN

#define ROUND   ROUND_SF
#define INPUT   INPUT_SF

#else

/*
 * Round function R, on base j. The value j is such that B[0] is actually
 * b[j] after the initial rotation. On the 13-round macro, j has the
 * successive values 12, 11, 10... 1, 0.
 */
#define ROUND(j)   do { \
		ACC_b(M13_A(1, j), 0) ^= a ## 1; \
		ACC_b(M13_A(2, j), 1) ^= a ## 2; \
		ACC_b(M13_A(3, j), 2) ^= a ## 3; \
		ACC_b(M13_A(4, j), 0) ^= a ## 4; \
		ACC_b(M13_A(5, j), 1) ^= a ## 5; \
		ACC_b(M13_A(6, j), 2) ^= a ## 6; \
		ACC_b(M13_A(7, j), 0) ^= a ## 7; \
		ACC_b(M13_A(8, j), 1) ^= a ## 8; \
		ACC_b(M13_A(9, j), 2) ^= a ## 9; \
		ACC_b(M13_A(10, j), 0) ^= a ## 10; \
		ACC_b(M13_A(11, j), 1) ^= a ## 11; \
		ACC_b(M13_A(12, j), 2) ^= a ## 12; \
		MILL; \
		a ## 13 ^= ACC_b(j, 0); \
		a ## 14 ^= ACC_b(j, 1); \
		a ## 15 ^= ACC_b(j, 2); \
	} while (0)

#define INPUT(j, p0, p1, p2)   do { \
		ACC_b(M13_A(1, j), 0) ^= (p0); \
		ACC_b(M13_A(1, j), 1) ^= (p1); \
		ACC_b(M13_A(1, j), 2) ^= (p2); \
		a16 ^= (p0); \
		a17 ^= (p1); \
		a18 ^= (p2); \
	} while (0)

#endif

#define MUL13(action)   do { \
		action(0); \
		action(1); \
		action(2); \
		action(3); \
		action(4); \
		action(5); \
		action(6); \
		action(7); \
		action(8); \
		action(9); \
		action(10); \
		action(11); \
		action(12); \
	} while (0)

#define MILL_READ_ELT(i)   do { \
		a ## i = sc->a[i]; \
	} while (0)

#define MILL_WRITE_ELT(i)   do { \
		sc->a[i] = a ## i; \
	} while (0)

#define STATE_READ_SF   do { \
		MUL19(MILL_READ_ELT); \
	} while (0)

#define STATE_WRITE_SF   do { \
		MUL19(MILL_WRITE_ELT); \
	} while (0)

#define PUSH13_SF   do { \
		WT DECL19(a); \
		const unsigned char *buf; \
 \
		buf = data; \
		STATE_READ_SF; \
		while (len >= sizeof sc->data) { \
			size_t mk; \
			for (mk = 13; mk > 0; mk --) { \
				WT p0 = INW(0, 0); \
				WT p1 = INW(0, 1); \
				WT p2 = INW(0, 2); \
				INPUT_SF(mk - 1, p0, p1, p2); \
				ROUND_SF(mk - 1); \
				buf += (sizeof sc->data) / 13; \
				len -= (sizeof sc->data) / 13; \
			} \
		} \
		STATE_WRITE_SF; \
		return len; \
	} while (0)

#if SPH_SMALL_FOOTPRINT_RADIOGATUN

#define STATE_READ    STATE_READ_SF
#define STATE_WRITE   STATE_WRITE_SF
#define PUSH13        PUSH13_SF

#else

#define BELT_READ_ELT(i)   do { \
		b ## i ## _0 = sc->b[3 * i + 0]; \
		b ## i ## _1 = sc->b[3 * i + 1]; \
		b ## i ## _2 = sc->b[3 * i + 2]; \
	} while (0)

#define BELT_WRITE_ELT(i)   do { \
		sc->b[3 * i + 0] = b ## i ## _0; \
		sc->b[3 * i + 1] = b ## i ## _1; \
		sc->b[3 * i + 2] = b ## i ## _2; \
	} while (0)

#define STATE_READ   do { \
		MUL13(BELT_READ_ELT); \
		MUL19(MILL_READ_ELT); \
	} while (0)

#define STATE_WRITE   do { \
		MUL13(BELT_WRITE_ELT); \
		MUL19(MILL_WRITE_ELT); \
	} while (0)

/*
 * Input data by chunks of 13*3 blocks. This is the body of the
 * radiogatun32_push13() and radiogatun64_push13() functions.
 */
#define PUSH13   do { \
		WT DECL19(a), DECL13(b); \
		const unsigned char *buf; \
 \
		buf = data; \
		STATE_READ; \
		while (len >= sizeof sc->data) { \
			WT p0, p1, p2; \
			MUL13(PUSH13_ELT); \
			buf += sizeof sc->data; \
			len -= sizeof sc->data; \
		} \
		STATE_WRITE; \
		return len; \
	} while (0)

#define PUSH13_ELT(k)   do { \
		p0 = INW(k, 0); \
		p1 = INW(k, 1); \
		p2 = INW(k, 2); \
		INPUT(M13_N(k), p0, p1, p2); \
		ROUND(M13_N(k)); \
	} while (0)

#endif

#define BLANK13_SF   do { \
		size_t mk = 13; \
		while (mk -- > 0) \
			ROUND_SF(mk); \
	} while (0)

#define BLANK1_SF   do { \
		WT tmp0, tmp1, tmp2; \
		ROUND_SF(12); \
		tmp0 = sc->b[36]; \
		tmp1 = sc->b[37]; \
		tmp2 = sc->b[38]; \
		memmove(sc->b + 3, sc->b, 36 * sizeof sc->b[0]); \
		sc->b[0] = tmp0; \
		sc->b[1] = tmp1; \
		sc->b[2] = tmp2; \
	} while (0)

#if SPH_SMALL_FOOTPRINT_RADIOGATUN

#define BLANK13   BLANK13_SF
#define BLANK1    BLANK1_SF

#else

/*
 * Run 13 blank rounds. This macro expects the "a" and "b" state variables
 * to be alread declared.
 */
#define BLANK13   MUL13(BLANK13_ELT)

#define BLANK13_ELT(k)   ROUND(M13_N(k))

#define MUL12(action)   do { \
		action(0); \
		action(1); \
		action(2); \
		action(3); \
		action(4); \
		action(5); \
		action(6); \
		action(7); \
		action(8); \
		action(9); \
		action(10); \
		action(11); \
	} while (0)

/*
 * Run a single blank round, and physically rotate the belt. This is used
 * for the last blank rounds, and the output rounds. This macro expects the
 * "a" abd "b" state variables to be already declared.
 */
#define BLANK1   do { \
		WT tmp0, tmp1, tmp2; \
		ROUND(12); \
		tmp0 = b0_0; \
		tmp1 = b0_1; \
		tmp2 = b0_2; \
		MUL12(BLANK1_ELT); \
		b1_0 = tmp0; \
		b1_1 = tmp1; \
		b1_2 = tmp2; \
	} while (0)

#define BLANK1_ELT(i)   do { \
		ACC_b(M13_A(M13_N(i), 1), 0) = ACC_b(M13_N(i), 0); \
		ACC_b(M13_A(M13_N(i), 1), 1) = ACC_b(M13_N(i), 1); \
		ACC_b(M13_A(M13_N(i), 1), 2) = ACC_b(M13_N(i), 2); \
	} while (0)

#endif

#define NO_TOKEN

/*
 * Perform padding, then blank rounds, then output some words. This is
 * the body of sph_radiogatun32_close() and sph_radiogatun64_close().
 */
#define CLOSE_SF(width)   CLOSE_GEN(width, \
                          NO_TOKEN, STATE_READ_SF, BLANK1_SF, BLANK13_SF)

#if SPH_SMALL_FOOTPRINT_RADIOGATUN
#define CLOSE          CLOSE_SF
#else
#define CLOSE(width)   CLOSE_GEN(width, \
                       WT DECL13(b);, STATE_READ, BLANK1, BLANK13)
#endif

#define CLOSE_GEN(width, WTb13, state_read, blank1, blank13)   do { \
		unsigned ptr, num; \
		unsigned char *out; \
		WT DECL19(a); \
		WTb13 \
 \
		ptr = sc->data_ptr; \
		sc->data[ptr ++] = 0x01; \
		memset(sc->data + ptr, 0, (sizeof sc->data) - ptr); \
		radiogatun ## width ## _push13(sc, sc->data, sizeof sc->data); \
 \
		num = 17; \
		for (;;) { \
			ptr += 3 * (width >> 3); \
			if (ptr > sizeof sc->data) \
				break; \
			num --; \
		} \
 \
		state_read; \
		if (num >= 13) { \
			blank13; \
			num -= 13; \
		} \
		while (num -- > 0) \
			blank1; \
 \
		num = 0; \
		out = dst; \
		for (;;) { \
			OUTW(out, a1); \
			out += width >> 3; \
			OUTW(out, a2); \
			out += width >> 3; \
			num += 2 * (width >> 3); \
			if (num >= 32) \
				break; \
			blank1; \
		} \
		INIT; \
	} while (0)

/*
 * Initialize context structure.
 */
#if SPH_LITTLE_ENDIAN || SPH_BIG_ENDIAN

#define INIT   do { \
		memset(sc->a, 0, sizeof sc->a); \
		memset(sc->b, 0, sizeof sc->b); \
		sc->data_ptr = 0; \
	} while (0)

#else

#define INIT   do { \
		size_t u; \
		for (u = 0; u < 19; u ++) \
			sc->a[u] = 0; \
		for (u = 0; u < 39; u ++) \
			sc->b[u] = 0; \
		sc->data_ptr = 0; \
	} while (0)

#endif

/* ======================================================================= */
/*
 * RadioGatun[32].
 */

#if !SPH_NO_RG32

#undef WT
#define WT           sph_u32
#undef T
#define T            SPH_T32
#undef ROR
#define ROR(x, n)    SPH_T32(((x) << ((32 - (n)) & 31)) | ((x) >> ((n) & 31)))
#undef INW
#define INW(i, j)    sph_dec32le_aligned(buf + (4 * (3 * (i) + (j))))
#undef OUTW
#define OUTW(b, v)   sph_enc32le(b, v)

/*
 * Insert data by big chunks of 13*12 = 156 bytes. Returned value is the
 * number of remaining bytes (between 0 and 155). This method assumes that
 * the input data is suitably aligned.
 */
static size_t
radiogatun32_push13(sph_radiogatun32_context *sc, const void *data, size_t len)
{
	PUSH13;
}

/* see sph_radiogatun.h */
void
sph_radiogatun32_init(void *cc)
{
	sph_radiogatun32_context *sc;

	sc = cc;
	INIT;
}

#ifdef SPH_UPTR
static void
radiogatun32_short(void *cc, const void *data, size_t len)
#else
/* see sph_radiogatun.h */
void
sph_radiogatun32(void *cc, const void *data, size_t len)
#endif
{
	sph_radiogatun32_context *sc;
	unsigned ptr;

	sc = cc;
	ptr = sc->data_ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->data) - ptr;
		if (clen > len)
			clen = len;
		memcpy(sc->data + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->data) {
			radiogatun32_push13(sc, sc->data, sizeof sc->data);
			ptr = 0;
		}
	}
	sc->data_ptr = ptr;
}

#ifdef SPH_UPTR
/* see sph_radiogatun.h */
void
sph_radiogatun32(void *cc, const void *data, size_t len)
{
	sph_radiogatun32_context *sc;
	unsigned ptr;
	size_t rlen;

	if (len < (2 * sizeof sc->data)) {
		radiogatun32_short(cc, data, len);
		return;
	}
	sc = cc;
	ptr = sc->data_ptr;
	if (ptr > 0) {
		unsigned t;

		t = (sizeof sc->data) - ptr;
		radiogatun32_short(sc, data, t);
		data = (const unsigned char *)data + t;
		len -= t;
	}
#if !SPH_UNALIGNED
	if (((SPH_UPTR)data & 3) != 0) {
		radiogatun32_short(sc, data, len);
		return;
	}
#endif
	rlen = radiogatun32_push13(sc, data, len);
	memcpy(sc->data, (const unsigned char *)data + len - rlen, rlen);
	sc->data_ptr = rlen;
}
#endif

/* see sph_radiogatun.h */
void
sph_radiogatun32_close(void *cc, void *dst)
{
	sph_radiogatun32_context *sc;

	sc = cc;
	CLOSE(32);
}

#endif

/* ======================================================================= */
/*
 * RadioGatun[64]. Compiled only if a 64-bit or more type is available.
 */

#if SPH_64

#if !SPH_NO_RG64

#undef WT
#define WT           sph_u64
#undef T
#define T            SPH_T64
#undef ROR
#define ROR(x, n)    SPH_T64(((x) << ((64 - (n)) & 63)) | ((x) >> ((n) & 63)))
#undef INW
#define INW(i, j)    sph_dec64le_aligned(buf + (8 * (3 * (i) + (j))))
#undef OUTW
#define OUTW(b, v)   sph_enc64le(b, v)

/*
 * On 32-bit x86, register pressure is such that using the small
 * footprint version is a net gain (x2 speed), because that variant
 * uses fewer local variables.
 */
#if SPH_I386_MSVC || SPH_I386_GCC || defined __i386__
#undef PUSH13
#define PUSH13   PUSH13_SF
#undef CLOSE
#define CLOSE    CLOSE_SF
#endif

/*
 * Insert data by big chunks of 13*24 = 312 bytes. Returned value is the
 * number of remaining bytes (between 0 and 311). This method assumes that
 * the input data is suitably aligned.
 */
static size_t
radiogatun64_push13(sph_radiogatun64_context *sc, const void *data, size_t len)
{
	PUSH13;
}

/* see sph_radiogatun.h */
void
sph_radiogatun64_init(void *cc)
{
	sph_radiogatun64_context *sc;

	sc = cc;
	INIT;
}

#ifdef SPH_UPTR
static void
radiogatun64_short(void *cc, const void *data, size_t len)
#else
/* see sph_radiogatun.h */
void
sph_radiogatun64(void *cc, const void *data, size_t len)
#endif
{
	sph_radiogatun64_context *sc;
	unsigned ptr;

	sc = cc;
	ptr = sc->data_ptr;
	while (len > 0) {
		size_t clen;

		clen = (sizeof sc->data) - ptr;
		if (clen > len)
			clen = len;
		memcpy(sc->data + ptr, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		ptr += clen;
		if (ptr == sizeof sc->data) {
			radiogatun64_push13(sc, sc->data, sizeof sc->data);
			ptr = 0;
		}
	}
	sc->data_ptr = ptr;
}

#ifdef SPH_UPTR
/* see sph_radiogatun.h */
void
sph_radiogatun64(void *cc, const void *data, size_t len)
{
	sph_radiogatun64_context *sc;
	unsigned ptr;
	size_t rlen;

	if (len < (2 * sizeof sc->data)) {
		radiogatun64_short(cc, data, len);
		return;
	}
	sc = cc;
	ptr = sc->data_ptr;
	if (ptr > 0) {
		unsigned t;

		t = (sizeof sc->data) - ptr;
		radiogatun64_short(sc, data, t);
		data = (const unsigned char *)data + t;
		len -= t;
	}
#if !SPH_UNALIGNED
	if (((SPH_UPTR)data & 7) != 0) {
		radiogatun64_short(sc, data, len);
		return;
	}
#endif
	rlen = radiogatun64_push13(sc, data, len);
	memcpy(sc->data, (const unsigned char *)data + len - rlen, rlen);
	sc->data_ptr = rlen;
}
#endif

/* see sph_radiogatun.h */
void
sph_radiogatun64_close(void *cc, void *dst)
{
	sph_radiogatun64_context *sc;

	sc = cc;
	CLOSE(64);
}

#endif

#endif
