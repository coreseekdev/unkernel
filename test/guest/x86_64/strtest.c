/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> */
/* x86-64 guest: the string instructions libc's memory helpers use (rep
 * movs/stos, byte scans) plus qsort calls through the function ABI. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d\n", __LINE__); fails++; } } while (0)

static int cmp(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void) {
    char big[4096], copy[4096];
    for (int i = 0; i < 4096; i++) big[i] = (char)(i * 7);
    memcpy(copy, big, 4096);
    CHECK(memcmp(copy, big, 4096) == 0);
    memmove(copy + 1, copy, 4000);
    CHECK(copy[1] == big[0] && copy[4000] == big[3999]);
    memset(big, 0x5a, 4096);
    CHECK(big[0] == 0x5a && big[4095] == 0x5a);

    const char *hay = "the quick brown fox jumps over the lazy dog";
    CHECK(strchr(hay, 'q') == hay + 4);
    CHECK(strstr(hay, "brown") == hay + 10);
    CHECK(strlen(hay) == 43);
    CHECK(memchr(hay, 'd', 43) == hay + 40);

    int v[9] = { 5, 3, 8, 1, 9, 2, 7, 4, 6 };
    qsort(v, 9, sizeof v[0], cmp);
    CHECK(v[0] == 1 && v[4] == 5 && v[8] == 9);

    if (fails) { printf("str failures=%d\n", fails); return 1; }
    printf("str ok\n");
    return 0;
}
