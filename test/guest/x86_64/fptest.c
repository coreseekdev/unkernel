/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> */
/* x86-64 guest: double/float arithmetic, comparisons and conversions. */
#include <stdio.h>
#include <math.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %d\n", __LINE__); fails++; } } while (0)

volatile double gd = 1.5;
volatile float gf = 2.25f;

int main(void) {
    double a = 3.141592653589793;
    double b = 2.718281828459045;
    CHECK(fabs((a + b) - 5.859874482048838) < 1e-15);
    CHECK(fabs((a * b) - 8.539734222673566) < 1e-15);
    CHECK(fabs((a / b) - 1.1557273497909217) < 1e-15);
    CHECK(sqrt(2.0) > 1.4142135623 && sqrt(2.0) < 1.4142135624);
    CHECK(floor(-2.5) == -3.0);
    CHECK(ceil(-2.5) == -2.0);
    CHECK(fmod(7.5, 2.0) == 1.5);

    float f = 1.0f / 3.0f;
    CHECK(f > 0.3333333f && f < 0.3333334f);
    CHECK((double)f > 0.33333331 && (double)f < 0.33333335);

    int i = (int)(gd * 4.0);
    CHECK(i == 6);
    long long ll = (long long)(a * 1e9);
    CHECK(ll == 3141592653LL);
    double back = (double)ll / 1e9;
    CHECK(fabs(back - a) < 1e-9);

    unsigned u = (unsigned)(gf * 4.0f);
    CHECK(u == 9);

    if (fails) { printf("fp failures=%d\n", fails); return 1; }
    printf("fp ok\n");
    return 0;
}
