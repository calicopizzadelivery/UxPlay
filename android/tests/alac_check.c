/*
 * Host check of the ALAC decoder, driven the way cb_audio_process in
 * uxplay_jni.c drives it: input copied into a zero-padded buffer, output
 * limited to one frame. It checks that a verbatim stereo frame decodes
 * bit-exactly, then feeds random and header-mutated frames looking for
 * memory faults. Not part of any build:
 *
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize=shift,signed-integer-overflow \
 *       -w -Iandroid/alac android/tests/alac_check.c android/alac/alac.c -lm -o alac_check
 *   ASAN_OPTIONS=detect_leaks=0 ./alac_check 100000
 *
 * The unhardened decoder faults within seconds of this; see the commit that
 * added it. The signed-shift and overflow reports it leaves out are
 * arithmetic on garbage input, not memory access.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alac.h"

#define SPF 352
static alac_file *a;
static unsigned char in_pad[4096 * 15 + 1024];

static void setup(void) {
    a = alac_create(16, 2);
    a->setinfo_max_samples_per_frame = SPF; a->setinfo_7a = 0; a->setinfo_sample_size = 16;
    a->setinfo_rice_historymult = 40; a->setinfo_rice_initialhistory = 10;
    a->setinfo_rice_kmodifier = 14; a->setinfo_7f = 2; a->setinfo_80 = 255;
    a->setinfo_82 = 0; a->setinfo_86 = 0; a->setinfo_8a_rate = 44100;
    alac_allocate_buffers(a);
}

static int decode(const unsigned char *data, int len, int16_t *pcm) {
    if (len > (int)sizeof(in_pad)) return 0;
    memcpy(in_pad, data, len);
    memset(in_pad + len, 0, sizeof(in_pad) - len);
    int out = SPF * 4;
    alac_decode_frame(a, in_pad, pcm, &out);
    return out;
}

/* bit writer */
static unsigned char buf[8192]; static int bitpos;
static void put(uint32_t v, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        if ((v >> i) & 1) buf[bitpos >> 3] |= 0x80 >> (bitpos & 7);
        bitpos++;
    }
}

int main(int argc, char **argv) {
    setup();
    static int16_t pcm[4096 * 2];
    /* 1: a verbatim stereo frame round-trips */
    memset(buf, 0, sizeof(buf)); bitpos = 0;
    put(1, 3); put(0, 4); put(0, 12); put(0, 1); put(0, 2); put(1, 1);
    int16_t want[SPF * 2];
    for (int i = 0; i < SPF; i++) {
        want[2 * i] = (int16_t)(18000 * sin(2 * M_PI * 440 * i / 44100.0));
        want[2 * i + 1] = (int16_t)(-want[2 * i] / 2);
        put((uint16_t)want[2 * i], 16); put((uint16_t)want[2 * i + 1], 16);
    }
    put(7, 3);
    int out = decode(buf, (bitpos + 7) / 8, pcm);
    int ok = out == SPF * 4 && memcmp(pcm, want, sizeof(want)) == 0;
    printf("verbatim frame: %d bytes out, %s\n", out, ok ? "matches" : "MISMATCH");

    /* 2: fuzz. Random frames, and the verbatim frame with header bits flipped */
    long n = argc > 1 ? atol(argv[1]) : 200000;
    srand(1);
    unsigned char f[4096];
    int good = (bitpos + 7) / 8;
    for (long i = 0; i < n; i++) {
        int len;
        if (i & 1) {
            len = rand() % 64;
            for (int j = 0; j < len; j++) f[j] = rand();
        } else {
            len = rand() % (good + 1);
            memcpy(f, buf, good);
            for (int k = rand() % 6; k >= 0; k--) f[rand() % 12] ^= 1 << (rand() % 8);
        }
        decode(f, len, pcm);
    }
    printf("fuzz: %ld frames, no fault\n", n);
    return ok ? 0 : 1;
}
