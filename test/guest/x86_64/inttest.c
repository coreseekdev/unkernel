/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> */
/* x86-64 guest: the integer baseline (flags, shifts, multiply/divide, bit
 * ops, 64-bit arithmetic, string and memory helpers). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d\n", __LINE__); fails++; } } while (0)

volatile int64_t s64a = -1234567890123LL, s64b = 97;

int main(void) {
    volatile uint32_t a = 0x12345678, b = 0x9abcdef0;
    CHECK((a + b) == 0xacf13568u);
    CHECK((a - b) == 0x77777788u);
    CHECK((a & b) == 0x12345670u);
    CHECK((a | b) == 0x9abcdef8u);
    CHECK((a ^ b) == 0x88888888u);
    CHECK((a << 5) == 0x468acf00u);
    CHECK((a >> 5) == 0x0091a2b3u);
    CHECK(((int32_t)0x92345678 >> 5) == (int32_t)0xfc91a2b3);
    CHECK((a / 7) == 0x0299c335u);
    CHECK((a % 7) == 0x00000005u);

    volatile int32_t n = -12345;
    CHECK(n * 3 == -37035);
    CHECK(n / 7 == -1763);
    CHECK(n % 7 == -4);
    CHECK((n << 3) == -98760);

    volatile uint64_t x = 0x0123456789abcdefULL, y = 0xfedcba9876543210ULL;
    CHECK((x + y) == 0xffffffffffffffffULL);
    CHECK((x ^ y) == 0xffffffffffffffffULL);
    CHECK(__builtin_bswap64(x) == 0xefcdab8967452301ULL);
    CHECK(__builtin_popcountll(x) == 32);
    CHECK(__builtin_clzll(x) == 7);
    CHECK(__builtin_ctzll(x) == 0);

    s64a = s64a / s64b;
    CHECK(s64a == -12727504021LL);

    char buf[64], src[64];
    memset(src, 'q', sizeof src);
    memcpy(buf, src, sizeof src);
    CHECK(buf[0] == 'q' && buf[63] == 'q');
    memset(buf, 0, sizeof buf);
    CHECK(strlen(buf) == 0);
    strcpy(buf, "the quick brown fox");
    CHECK(strcmp(buf, "the quick brown fox") == 0);
    CHECK(strncmp(buf, "the slow", 4) == 0);

    unsigned long h = 5381;
    for (const char *p = buf; *p; p++) h = h * 33 + (unsigned char)*p;
    printf("hash=%lx\n", h);

    if (fails) { printf("int failures=%d\n", fails); return 1; }
    printf("int ok\n");
    return 0;
}
