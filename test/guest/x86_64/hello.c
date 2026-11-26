/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> */
/* x86-64 guest: libc startup, stdio, argv/envp and a clean exit. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    printf("hello x86_64\n");
    printf("argc=%d\n", argc);
    const char *env = getenv("HOME");
    printf("HOME=%s\n", env ? env : "(null)");
    return 0;
}
