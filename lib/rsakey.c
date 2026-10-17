/**
 * Classic AirPlay 1 / RAOP session-key unwrap.
 *
 * macOS drives all audio-only AirPlay over classic RAOP and encrypts the
 * session key to the AirPort Express public key, sending it as the SDP
 * attribute "a=rsaaeskey". Unwrapping it needs the matching private key.
 *
 * WHY THIS AND NOT FAIRPLAY. The receiver advertises which key exchanges it
 * supports in the _raop._tcp "et" record: 1 = RSA, 3 = FairPlay, 5 = FairPlay
 * SAPv2.5. UxPlay offered 3 and 5, so a Mac sent "a=fpaeskey" -- but
 * lib/playfair implements exactly one derivation, correct only for a FairPlay
 * version-0x03 key message, and macOS sends version 0x02 whatever we
 * advertise. Tested on the bench 2026-10-17 with et="0,3,5", "0,5" and "0":
 * the Mac sent 0x02 every time, and even with et="0" it still encrypted
 * rather than streaming in clear. The wrong key decrypts to random bytes,
 * which ALAC renders as ~40% duty-cycle noise with a 2:1 left/right channel
 * ratio -- see docs/airplay.md for the measurement that identified it. RSA is
 * the only key exchange both macOS and this receiver can complete.
 *
 * PROVENANCE, AND THE DECISION TO CARRY IT. The key lives in
 * lib/airport_key.h as AIRPORT_KEY_PEM. It is Apple's, recovered from the
 * AirPort Express firmware in 2011 and public ever since; shairport-sync has
 * carried it in common.c for over a decade and ships that way in Debian,
 * Ubuntu and Homebrew. It is the only means by which an independent receiver
 * can accept AirPlay 1 audio at all. Including it, and tracking it in git,
 * was the project owner's explicit decision, taken 2026-10-17 after the
 * alternatives were set out: unencrypted (macOS refuses it -- tested),
 * FairPlay 0x02 (would mean reverse-engineering Apple's DRM), or this.
 *
 * Nothing is owed to anyone until an image is distributed, and distribution
 * is RAIL 18b -- read docs/source-release.md before publishing a build that
 * contains this file.
 *
 * If AIRPORT_KEY_PEM is undefined the file still builds, and every classic
 * RAOP session fails cleanly with a log line rather than playing noise.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "crypto.h"

#if defined(__has_include)
#if __has_include("airport_key.h")
#include "airport_key.h"
#endif
#endif

#ifdef AIRPORT_KEY_PEM
/** Load the key once per call. Not hot: at most one decrypt and one sign per
    RTSP request. */
static EVP_PKEY *airport_key_load(void)
{
    BIO *bmem = BIO_new_mem_buf(AIRPORT_KEY_PEM, -1);
    if (!bmem) {
        return NULL;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bmem, NULL, NULL, NULL);
    BIO_free(bmem);
    return key;
}
#endif

int
rsa_auth_sign(const unsigned char *input, int inlen,
              unsigned char *output, int outlen)
{
#ifndef AIRPORT_KEY_PEM
    (void) input; (void) inlen; (void) output; (void) outlen;
    return -2;
#else
    /* The classic RAOP "Apple-Challenge" is answered by RSA-signing
       challenge || local-IP || MAC with PKCS#1 v1.5 padding and returning it
       base64 in "Apple-Response". shairport-sync does the same thing in
       apple_challenge() via rsa_apply(..., RSA_MODE_AUTH). Without it a Mac
       closes the connection straight after OPTIONS and reports the receiver
       as incompatible. */
    int ret = -1;
    EVP_PKEY *key = airport_key_load();
    if (!key) {
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx) {
        size_t ol = 0;
        if (EVP_PKEY_sign_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
            EVP_PKEY_sign(ctx, NULL, &ol, input, (size_t) inlen) > 0 &&
            ol <= (size_t) outlen) {
            size_t got = ol;
            if (EVP_PKEY_sign(ctx, output, &got, input, (size_t) inlen) > 0) {
                ret = (int) got;
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(key);
    return ret;
#endif
}

int
rsa_aeskey_decrypt(const unsigned char *input, int inlen,
                   unsigned char *output, int outlen)
{
#ifndef AIRPORT_KEY_PEM
    (void) input; (void) inlen; (void) output; (void) outlen;
    return -2;   /* no key configured; the caller reports it once, clearly */
#else
    int ret = -1;
    EVP_PKEY *key = airport_key_load();
    if (!key) {
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx) {
        size_t ol = 0;
        /* OAEP, as the sender used; shairport-sync does the same in
           rsa_apply() with RSA_MODE_KEY. */
        if (EVP_PKEY_decrypt_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
            EVP_PKEY_decrypt(ctx, NULL, &ol, input, (size_t) inlen) > 0 &&
            ol > 0) {
            /* ol here is the MAXIMUM plaintext size -- the modulus size, 256
               bytes for RSA-2048 -- not the length of this plaintext. The
               session key is 16 bytes, so comparing ol against outlen before
               decrypting rejects every valid ciphertext. Allocate ol, decrypt,
               and check the length that comes back. */
            unsigned char *tmp = malloc(ol);
            if (tmp) {
                size_t got = ol;
                if (EVP_PKEY_decrypt(ctx, tmp, &got, input, (size_t) inlen) > 0 &&
                    got <= (size_t) outlen) {
                    memcpy(output, tmp, got);
                    ret = (int) got;
                }
                /* the plaintext is the session key; do not leave it on the heap */
                OPENSSL_cleanse(tmp, ol);
                free(tmp);
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(key);
    return ret;
#endif
}
