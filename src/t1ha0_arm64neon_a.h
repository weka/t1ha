/*
 *  Copyright (c) 2016-2020 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2020 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  Portions Copyright (c) 2024 Weka.IO, Inc.
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will (be) Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#include "t1ha_bits.h"
#include "t1ha_selfcheck.h"

#if T1HA0_NEON_AVAILABLE
#include "sse2neon.h"

uint64_t t1ha0_arm64aes_neon(const void *data, size_t len, uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = len;

  if (unlikely(len > 32)) {
    __m128i x = _mm_set_epi64x(a, b);
    __m128i y = _mm_aesenc_si128(x, _mm_set_epi64x(prime_5, prime_6));

    const __m128i *__restrict v = (const __m128i *)data;
    const __m128i *__restrict const detent =
        (const __m128i *)((const uint8_t *)data + len - 127);

    while (v < detent) {
      __m128i v0 = _mm_loadu_si128(v + 0);
      __m128i v1 = _mm_loadu_si128(v + 1);
      __m128i v2 = _mm_loadu_si128(v + 2);
      __m128i v3 = _mm_loadu_si128(v + 3);
      __m128i v4 = _mm_loadu_si128(v + 4);
      __m128i v5 = _mm_loadu_si128(v + 5);
      __m128i v6 = _mm_loadu_si128(v + 6);
      __m128i v7 = _mm_loadu_si128(v + 7);

      __m128i v0y = _mm_aesenc_si128(v0, y);
      __m128i v2x6 = _mm_aesenc_si128(v2, _mm_xor_si128(x, v6));
      __m128i v45_67 =
          _mm_xor_si128(_mm_aesenc_si128(v4, v5), _mm_add_epi64(v6, v7));

      __m128i v0y7_1 = _mm_aesdec_si128(_mm_sub_epi64(v7, v0y), v1);
      __m128i v2x6_3 = _mm_aesenc_si128(v2x6, v3);

      x = _mm_aesenc_si128(v45_67, _mm_add_epi64(x, y));
      y = _mm_aesenc_si128(v2x6_3, _mm_xor_si128(v0y7_1, v5));
      v += 8;
    }

    if (len & 64) {
      __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
      __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
      x = _mm_aesdec_si128(x, v0y);
      y = _mm_aesdec_si128(y, v1x);

      __m128i v2y = _mm_add_epi64(y, _mm_loadu_si128(v++));
      __m128i v3x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
      x = _mm_aesdec_si128(x, v2y);
      y = _mm_aesdec_si128(y, v3x);
    }

    if (len & 32) {
      __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
      __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
      x = _mm_aesdec_si128(x, v0y);
      y = _mm_aesdec_si128(y, v1x);
    }

    if (len & 16) {
      y = _mm_add_epi64(x, y);
      x = _mm_aesdec_si128(x, _mm_loadu_si128(v++));
    }

    x = _mm_add_epi64(_mm_aesdec_si128(x, _mm_aesenc_si128(y, x)), y);
    a = _mm_extract_epi64(x, 0);
    b = _mm_extract_epi64(x, 1);
    data = v;
    len &= 15;
  }

  const uint64_t *v = (const uint64_t *)data;
  switch (len) {
  default:
    mixup64(&a, &b, fetch64_le_unaligned(v++), prime_4);
  /* fall through */
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    mixup64(&b, &a, fetch64_le_unaligned(v++), prime_3);
  /* fall through */
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    mixup64(&a, &b, fetch64_le_unaligned(v++), prime_2);
  /* fall through */
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    mixup64(&b, &a, tail64_le_unaligned(v, len), prime_1);
  /* fall through */
  case 0:
    return final64(a, b);
  }
}

#endif /* T1HA0_NEON_AVAILABLE */
