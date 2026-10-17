/**
 *  Copyright (C) 2012  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *==================================================================
 * modified by fduncanh 2022
 */

#ifndef DNSSDINT_H
#define DNSSDINT_H

#include "global.h"

/* the previous behavior of announcing UxPlay with a fixed public key PK
 * can be restored by uncommenting the following line  */
//#define PK "b07727d6f6cd6e08b58ede525ec3cdeaa252ad9f683feb212ef8a205246554e7"

#define RAOP_TXTVERS "1"
#define RAOP_CH "2"             /* Audio channels: 2 */
#define RAOP_CN "0,1,2,3"       /* Audio codec: PCM, ALAC, AAC, AAC ELD */
/* Encryption type: None, FairPlay SAPv2.5. "3" (plain FairPlay) is NOT
   advertised: lib/playfair implements exactly one key derivation
   (playfair.c:13), and it is only correct for the version-0x03 key message.
   A macOS sender offered "3" picks it, sends FPLY version 0x02, and
   fairplay_decrypt then returns 16 bytes that are not the session key -- the
   audio decrypts to random bytes, ALAC parses them as a uniformly random
   3-bit channel tag, and the result is ~40%% duty-cycle bursts of noise with
   a 2:1 left/right ratio. Measured off HDMI 2026-10-17; see docs/airplay.md.

   "5" is gone too, for now: macOS sends a version-0x02 key message whatever
   we advertise, so neither FairPlay variant yields a usable key. "1" is RSA,
   which is what shairport-sync offers (bonjour_strings.c:87) and unwraps with
   Apple's leaked AirPort Express private key -- we carry no such key. So this
   offers encryption type 0 alone, to establish whether macOS will stream
   unencrypted on a LAN. If it will, no key of any kind is needed. */
#define RAOP_ET "0,1"
#define RAOP_VV "2"
#define FEATURES_1 "0x5A7FFEE6" /* first 32 bits of features, with bit 27 ("supports legacy pairing") ON */
//#define FEATURES_1 "0x527FFEE6" /* first 32 bits of features, with bit 27 ("supports legacy pairing") OFF */
#define FEATURES_2  "0x0"        /* second 32 bits of features */
#define RAOP_RHD "5.6.0.0"
#define RAOP_SF "0x4"
#define RAOP_SV "false"
#define RAOP_DA "true"
#define RAOP_SR "44100"         /* Sample rate: 44100 */
#define RAOP_SS "16"            /* Sample size: 16 */
#define RAOP_VS GLOBAL_VERSION  /* defined in global.h */
#define RAOP_TP "UDP"           /* Transport protocol. Possible values: UDP or TCP or TCP,UDP */
#define RAOP_MD "0,1,2"         /* Metadata: text, artwork, progress */
#define RAOP_VN "65537"

#define AIRPLAY_SRCVERS GLOBAL_VERSION /*defined in global.h */
#define AIRPLAY_FLAGS "0x84"
#define AIRPLAY_VV "2"
#define AIRPLAY_PI "2e388006-13ba-4041-9a67-25dd4a43d536"

#endif
