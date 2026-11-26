/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> */
/* x86-64 guest: explicit SSE2 (packed integer and scalar floating point). */
#include <stdio.h>
#include <stdint.h>
#include <emmintrin.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d\n", __LINE__); fails++; } } while (0)

int main(void) {
    __m128i a = _mm_set_epi32(4, 3, 2, 1);
    __m128i b = _mm_set_epi32(40, 30, 20, 10);
    __m128i s = _mm_add_epi32(a, b);
    int32_t out[4];
    _mm_storeu_si128((__m128i *)out, s);
    CHECK(out[0] == 11 && out[1] == 22 && out[2] == 33 && out[3] == 44);

    __m128i m = _mm_mullo_epi16(_mm_set1_epi16(300), _mm_set1_epi16(200));
    int16_t mo[8];
    _mm_storeu_si128((__m128i *)mo, m);
    CHECK(mo[0] == (int16_t)(300 * 200));

    __m128i x = _mm_set_epi64x(0x0123456789abcdefLL, 0xfedcba9876543210LL);
    int64_t xo[2];
    _mm_storeu_si128((__m128i *)xo, x);
    CHECK((uint64_t)xo[0] == 0xfedcba9876543210ULL);
    CHECK((uint64_t)xo[1] == 0x0123456789abcdefULL);

    __m128 fa = _mm_set_ps(4.0f, 3.0f, 2.0f, 1.0f);
    __m128 fb = _mm_set_ps(0.4f, 0.3f, 0.2f, 0.1f);
    __m128 fs = _mm_add_ps(fa, fb);
    float fo[4];
    _mm_storeu_ps(fo, fs);
    CHECK(fo[0] > 1.099f && fo[0] < 1.101f);
    CHECK(fo[3] > 4.399f && fo[3] < 4.401f);

    __m128d da = _mm_set_pd(2.5, 1.5);
    __m128d db = _mm_set_pd(10.0, 20.0);
    double dsum[2];
    _mm_storeu_pd(dsum, _mm_add_pd(da, db));
    CHECK(dsum[0] == 21.5 && dsum[1] == 12.5);

    __m128i cmp = _mm_cmpeq_epi32(a, a);
    int mask = _mm_movemask_epi8(cmp);
    CHECK((unsigned)mask == 0xffffu);

    __m128i shift = _mm_slli_epi32(a, 4);
    _mm_storeu_si128((__m128i *)out, shift);
    CHECK(out[0] == 16 && out[3] == 64);

    if (fails) { printf("sse2 failures=%d\n", fails); return 1; }
    printf("sse2 ok\n");
    return 0;
}
