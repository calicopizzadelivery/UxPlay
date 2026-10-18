/**
 *  Copyright (C) 2011-2012  Juho Vähä-Herttua
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
 *=================================================================
 * modified by fduncanh 2022
 */

/* These defines allow us to compile on iOS */
#ifndef __has_feature
# define __has_feature(x) 0
#endif
#ifndef __has_extension
# define __has_extension __has_feature
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "compat.h"
#include <dns_sd.h>
#include "dnssd.h"

#include "dnssdint.h"
#include "global.h"
#include "utils.h"

#define MAX_DEVICEID 18
#define MAX_SERVNAME 256

#if defined(HAVE_LIBDL) && !defined(__APPLE__)
# define USE_LIBDL 1
#else
# define USE_LIBDL 0
#endif

#if defined(_WIN32) || USE_LIBDL
# ifdef _WIN32
#  include <stdint.h>
#  if !defined(EFI32) && !defined(EFI64)
#   define DNSSD_STDCALL __stdcall
#  else
#   define DNSSD_STDCALL
#  endif
# else
#  include <dlfcn.h>
#  define DNSSD_STDCALL
# endif

typedef struct _DNSServiceRef_t *DNSServiceRef;
#ifndef _WIN32
typedef union _TXTRecordRef_t { char PrivateData[16]; char *ForceNaturalAlignment; } TXTRecordRef;
#endif
typedef uint32_t DNSServiceFlags;
typedef int32_t  DNSServiceErrorType;

typedef void (DNSSD_STDCALL *DNSServiceRegisterReply)
    (
    DNSServiceRef                       sdRef,
    DNSServiceFlags                     flags,
    DNSServiceErrorType                 errorCode,
    const char                          *name,
    const char                          *regtype,
    const char                          *domain,
    void                                *context
    );

#else
//# include <dns_sd.h>
# define DNSSD_STDCALL
#endif

typedef DNSServiceErrorType (DNSSD_STDCALL *DNSServiceRegister_t)
        (
                DNSServiceRef                       *sdRef,
                DNSServiceFlags                     flags,
                uint32_t                            interfaceIndex,
                const char                          *name,
                const char                          *regtype,
                const char                          *domain,
                const char                          *host,
                uint16_t                            port,
                uint16_t                            txtLen,
                const void                          *txtRecord,
                DNSServiceRegisterReply             callBack,
                void                                *context
        );
typedef void (DNSSD_STDCALL *DNSServiceRefDeallocate_t)(DNSServiceRef sdRef);
typedef void (DNSSD_STDCALL *TXTRecordCreate_t)
        (
                TXTRecordRef     *txtRecord,
                uint16_t         bufferLen,
                void             *buffer
        );
typedef void (DNSSD_STDCALL *TXTRecordDeallocate_t)(TXTRecordRef *txtRecord);
typedef DNSServiceErrorType (DNSSD_STDCALL *TXTRecordSetValue_t)
        (
                TXTRecordRef     *txtRecord,
                const char       *key,
                uint8_t          valueSize,
                const void       *value
        );
typedef uint16_t (DNSSD_STDCALL *TXTRecordGetLength_t)(const TXTRecordRef *txtRecord);
typedef const void * (DNSSD_STDCALL *TXTRecordGetBytesPtr_t)(const TXTRecordRef *txtRecord);


struct dnssd_s {
#ifdef WIN32
    HMODULE module;
#elif USE_LIBDL
    void *module;
#endif

    DNSServiceRegister_t       DNSServiceRegister;
    DNSServiceRefDeallocate_t  DNSServiceRefDeallocate;
    TXTRecordCreate_t          TXTRecordCreate;
    TXTRecordSetValue_t        TXTRecordSetValue;
    TXTRecordGetLength_t       TXTRecordGetLength;
    TXTRecordGetBytesPtr_t     TXTRecordGetBytesPtr;
    TXTRecordDeallocate_t      TXTRecordDeallocate;

    TXTRecordRef raop_record;
    TXTRecordRef airplay_record;
    TXTRecordRef legacy_record;

    DNSServiceRef raop_service;
    DNSServiceRef airplay_service;
    DNSServiceRef legacy_service;

    char *name;
    int name_len;

    char *hw_addr;
    int hw_addr_len;

    char *pk;

    uint32_t features1;
    uint32_t features2;

    unsigned char pin_pw;
};



dnssd_t *
dnssd_init(const char* name, int name_len, const char* hw_addr, int hw_addr_len, int *error, unsigned char pin_pw)
{
    /* pin_pw = 0: no pin or password
                1: use onscreen pin for client access control
                2 or 3: require password for client access control  
    */
    
    if (error) *error = DNSSD_ERROR_NOERROR;

    dnssd_t *dnssd = (dnssd_t *) calloc(1, sizeof(dnssd_t));
    if (!dnssd) {
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }

    dnssd->pin_pw = pin_pw;

    char *end = NULL;
    unsigned long features  = strtoul(FEATURES_1, &end, 16);
    if (!end || (features & 0xFFFFFFFF) != features) {
        free (dnssd);
        if (error) *error = DNSSD_ERROR_BADFEATURES;
        return NULL;
    } 
    dnssd->features1 = (uint32_t) features;

    features  = strtoul(FEATURES_2, &end, 16);
    if (!end || (features & 0xFFFFFFFF) != features) {
        free (dnssd);
        if (error) *error = DNSSD_ERROR_BADFEATURES;
        return NULL;
    } 
    dnssd->features2 = (uint32_t) features;

#ifdef WIN32
    dnssd->module = LoadLibraryA("dnssd.dll");
	if (!dnssd->module) {
		if (error) *error = DNSSD_ERROR_LIBNOTFOUND;
		free(dnssd);
		return NULL;
	}
	dnssd->DNSServiceRegister = (DNSServiceRegister_t)GetProcAddress(dnssd->module, "DNSServiceRegister");
	dnssd->DNSServiceRefDeallocate = (DNSServiceRefDeallocate_t)GetProcAddress(dnssd->module, "DNSServiceRefDeallocate");
	dnssd->TXTRecordCreate = (TXTRecordCreate_t)GetProcAddress(dnssd->module, "TXTRecordCreate");
	dnssd->TXTRecordSetValue = (TXTRecordSetValue_t)GetProcAddress(dnssd->module, "TXTRecordSetValue");
	dnssd->TXTRecordGetLength = (TXTRecordGetLength_t)GetProcAddress(dnssd->module, "TXTRecordGetLength");
	dnssd->TXTRecordGetBytesPtr = (TXTRecordGetBytesPtr_t)GetProcAddress(dnssd->module, "TXTRecordGetBytesPtr");
	dnssd->TXTRecordDeallocate = (TXTRecordDeallocate_t)GetProcAddress(dnssd->module, "TXTRecordDeallocate");

	if (!dnssd->DNSServiceRegister || !dnssd->DNSServiceRefDeallocate || !dnssd->TXTRecordCreate ||
	    !dnssd->TXTRecordSetValue || !dnssd->TXTRecordGetLength || !dnssd->TXTRecordGetBytesPtr ||
	    !dnssd->TXTRecordDeallocate) {
		if (error) *error = DNSSD_ERROR_PROCNOTFOUND;
		FreeLibrary(dnssd->module);
		free(dnssd);
		return NULL;
	}
#elif USE_LIBDL
    dnssd->module = dlopen("libdns_sd.so", RTLD_LAZY);
	if (!dnssd->module) {
		if (error) *error = DNSSD_ERROR_LIBNOTFOUND;
		free(dnssd);
		return NULL;
	}
	dnssd->DNSServiceRegister = (DNSServiceRegister_t)dlsym(dnssd->module, "DNSServiceRegister");
	dnssd->DNSServiceRefDeallocate = (DNSServiceRefDeallocate_t)dlsym(dnssd->module, "DNSServiceRefDeallocate");
	dnssd->TXTRecordCreate = (TXTRecordCreate_t)dlsym(dnssd->module, "TXTRecordCreate");
	dnssd->TXTRecordSetValue = (TXTRecordSetValue_t)dlsym(dnssd->module, "TXTRecordSetValue");
	dnssd->TXTRecordGetLength = (TXTRecordGetLength_t)dlsym(dnssd->module, "TXTRecordGetLength");
	dnssd->TXTRecordGetBytesPtr = (TXTRecordGetBytesPtr_t)dlsym(dnssd->module, "TXTRecordGetBytesPtr");
	dnssd->TXTRecordDeallocate = (TXTRecordDeallocate_t)dlsym(dnssd->module, "TXTRecordDeallocate");

	if (!dnssd->DNSServiceRegister || !dnssd->DNSServiceRefDeallocate || !dnssd->TXTRecordCreate ||
	    !dnssd->TXTRecordSetValue || !dnssd->TXTRecordGetLength || !dnssd->TXTRecordGetBytesPtr ||
	    !dnssd->TXTRecordDeallocate) {
		if (error) *error = DNSSD_ERROR_PROCNOTFOUND;
		dlclose(dnssd->module);
		free(dnssd);
		return NULL;
	}
#else
    dnssd->DNSServiceRegister = &DNSServiceRegister;
    dnssd->DNSServiceRefDeallocate = &DNSServiceRefDeallocate;
    dnssd->TXTRecordCreate = &TXTRecordCreate;
    dnssd->TXTRecordSetValue = &TXTRecordSetValue;
    dnssd->TXTRecordGetLength = &TXTRecordGetLength;
    dnssd->TXTRecordGetBytesPtr = &TXTRecordGetBytesPtr;
    dnssd->TXTRecordDeallocate = &TXTRecordDeallocate;
#endif

    dnssd->name_len = name_len;
    dnssd->name = calloc(1, name_len + 1);
    if (!dnssd->name) {
        free(dnssd);
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }
    memcpy(dnssd->name, name, name_len);

    dnssd->hw_addr_len = hw_addr_len;
    dnssd->hw_addr = calloc(1, dnssd->hw_addr_len);
    if (!dnssd->hw_addr) {
        free(dnssd->name);
        free(dnssd);
        if (error) *error = DNSSD_ERROR_OUTOFMEM;
        return NULL;
    }

    memcpy(dnssd->hw_addr, hw_addr, hw_addr_len);

    return dnssd;
}

void
dnssd_destroy(dnssd_t *dnssd)
{
    if (dnssd) {
#ifdef WIN32
        FreeLibrary(dnssd->module);
#elif USE_LIBDL
        dlclose(dnssd->module);
#endif
        free(dnssd);
    }
}

int
dnssd_register_raop(dnssd_t *dnssd, unsigned short port)
{
    char servname[MAX_SERVNAME];

    char features[22] = {0};

    assert(dnssd);

    snprintf(features, sizeof(features), "0x%X,0x%X", dnssd->features1, dnssd->features2);

    dnssd->TXTRecordCreate(&dnssd->raop_record, 0, NULL);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "ch", strlen(RAOP_CH), RAOP_CH);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "cn", strlen(RAOP_CN), RAOP_CN);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "da", strlen(RAOP_DA), RAOP_DA);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "et", strlen(RAOP_ET), RAOP_ET);
    /* "encryption key available" -- the legacy flag that says the RSA key
       exchange (et=1) can actually be completed. shairport-sync sets it in
       its classic branch (bonjour_strings.c:138) and is the only receiver
       macOS is known to drive over RSA; we never set it, which may be why a
       Mac reaches for FairPlay regardless of what "et" offers. */
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "ek", strlen("1"), "1");
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "vv", strlen(RAOP_VV), RAOP_VV);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "ft", strlen(features), features);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "am", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "md", strlen(RAOP_MD), RAOP_MD);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "rhd", strlen(RAOP_RHD), RAOP_RHD);
    switch (dnssd->pin_pw) {
    case 2:
    case 3:
        /* sf bit 7 (0x80) is "password required" */
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("true"), "true");
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "sf", strlen("0x84"), "0x84");
        break;
    case 1:
        /* sf bit 3 (0x08) is "pin required". The length was hard-coded 3 for a
           four-character value, which would have published "0x8" -- masked
           until now by the unconditional write below. */
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("true"), "true");
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "sf", strlen("0x8c"), "0x8c");
        break;
    default:
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "pw", strlen("false"), "false");
        dnssd->TXTRecordSetValue(&dnssd->raop_record, "sf", strlen(RAOP_SF), RAOP_SF);
        break;
    }
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "sr", strlen(RAOP_SR), RAOP_SR);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "ss", strlen(RAOP_SS), RAOP_SS);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "sv", strlen(RAOP_SV), RAOP_SV);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "tp", strlen(RAOP_TP), RAOP_TP);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "txtvers", strlen(RAOP_TXTVERS), RAOP_TXTVERS);
    /* No unconditional "sf" here: TXTRecordSetValue replaces rather than
       appends, so this clobbered the pin_pw branch above and the receiver
       never told a sender a code was required. */
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "vs", strlen(RAOP_VS), RAOP_VS);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "vn", strlen(RAOP_VN), RAOP_VN);
    dnssd->TXTRecordSetValue(&dnssd->raop_record, "pk", strlen(dnssd->pk), dnssd->pk);

    /* Convert hardware address to string */
    if (utils_hwaddr_raop(servname, sizeof(servname), dnssd->hw_addr, dnssd->hw_addr_len) < 0) {
        /* FIXME: handle better */
        return -1;
    }

    /* Check that we have bytes for 'hw@name' format */
    if (sizeof(servname) < strlen(servname) + 1 + dnssd->name_len + 1) {
        /* FIXME: handle better */
        return -2;
    }

    strncat(servname, "@", sizeof(servname)-strlen(servname)-1);
    strncat(servname, dnssd->name, sizeof(servname)-strlen(servname)-1);

    /* Register the service */
    DNSServiceErrorType retval = dnssd->DNSServiceRegister(&dnssd->raop_service, 0, 0,
                                                          servname, "_raop._tcp",
                                                          NULL, NULL,
                                                          htons(port),
                                                          dnssd->TXTRecordGetLength(&dnssd->raop_record),
                                                          dnssd->TXTRecordGetBytesPtr(&dnssd->raop_record),
                                                          NULL, NULL);

    return (int) retval;   /* error codes are listed in Apple's dns_sd.h */
}

/**
 * A SECOND _raop._tcp service that looks like a legacy AirPlay 1 device.
 *
 * macOS picks its key exchange by whether the receiver looks like AirPlay 2,
 * not by the "et" record: with _airplay._tcp advertised it demands FairPlay
 * version 0x02, which lib/playfair cannot unwrap, and it ignores every et/ek
 * combination (five were tested on the bench, 2026-10-17). Without
 * _airplay._tcp it uses the legacy RSA exchange, which works -- but dropping
 * _airplay._tcp costs mirroring, which needs it.
 *
 * So advertise both, as two apparently separate devices. This one carries a
 * different hardware address and a suffixed display name, and only the TXT
 * keys shairport-sync's classic branch sets (bonjour_strings.c:125-145): no
 * pk, ft, vs, sf, vv, am or rhd, which are the AirPlay 2 markers. A sender
 * that resolves this one finds no _airplay._tcp counterpart for it.
 *
 * Both point at the same RTSP port, so a session arriving here is served by
 * the same server, the same PIN gate and the same renderers. That is the
 * whole reason for doing it in-process rather than running a second daemon:
 * a shairport-sync sidecar would need its own SELinux domain, would not share
 * the PIN gate, and would have no route to the now-playing panel without
 * wiring its metadata pipe.
 *
 * UNVERIFIED as of 2026-10-17: this assumes macOS correlates the two service
 * types by service identity -- the hw address in "<HW>@<name>" and deviceid --
 * rather than by host or IP. If it correlates by host this cannot work, and
 * neither could a separate daemon on the same box, for the same reason. Test
 * with a Mac: it should send a=rsaaeskey to this name.
 */
int
dnssd_register_legacy(dnssd_t *dnssd, unsigned short port, const char *suffix,
                      int password_required)
{
    char servname[MAX_SERVNAME];
    char legacy_hw[MAX_HWADDR_LEN];

    assert(dnssd);
    assert(suffix);

    /* A distinct hardware address, derived from ours so it is stable across
       restarts, with the locally-administered bit set and the last byte
       altered so it cannot collide with the real one. */
    int hw_len = dnssd->hw_addr_len;
    if (hw_len <= 0 || hw_len > (int) sizeof(legacy_hw)) {
        return -1;
    }
    memcpy(legacy_hw, dnssd->hw_addr, (size_t) hw_len);
    legacy_hw[0] = (char) (legacy_hw[0] | 0x02);      /* locally administered */
    legacy_hw[hw_len - 1] = (char) (legacy_hw[hw_len - 1] ^ 0x01);

    dnssd->TXTRecordCreate(&dnssd->legacy_record, 0, NULL);
    /* Exactly shairport-sync's classic set, and nothing else. */
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "txtvers", strlen("1"), "1");
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "ch", strlen(RAOP_CH), RAOP_CH);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "cn", strlen("0,1"), "0,1");
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "da", strlen(RAOP_DA), RAOP_DA);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "et", strlen("0,1"), "0,1");
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "ek", strlen("1"), "1");
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "md", strlen(RAOP_MD), RAOP_MD);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "sr", strlen(RAOP_SR), RAOP_SR);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "ss", strlen(RAOP_SS), RAOP_SS);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "sv", strlen(RAOP_SV), RAOP_SV);
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "tp", strlen("TCP,UDP"), "TCP,UDP");
    dnssd->TXTRecordSetValue(&dnssd->legacy_record, "vn", strlen(RAOP_VN), RAOP_VN);
    /* Honest about whether a session here will actually be gated. Classic
       RAOP is audio by construction, so it is gated only when the pin is on
       AND "allow audio without a code" is off. Advertising pw=false while
       refusing without a code is the defect fixed in 4044c1b; do not
       reintroduce it on this record. */
    if (password_required) {
        dnssd->TXTRecordSetValue(&dnssd->legacy_record, "pw", strlen("true"), "true");
    } else {
        dnssd->TXTRecordSetValue(&dnssd->legacy_record, "pw", strlen("false"), "false");
    }

    if (utils_hwaddr_raop(servname, sizeof(servname), legacy_hw, hw_len) < 0) {
        return -1;
    }
    if (sizeof(servname) < strlen(servname) + 1 + (size_t) dnssd->name_len + strlen(suffix) + 1) {
        return -2;
    }
    strncat(servname, "@", sizeof(servname) - strlen(servname) - 1);
    strncat(servname, dnssd->name, sizeof(servname) - strlen(servname) - 1);
    strncat(servname, suffix, sizeof(servname) - strlen(servname) - 1);

    DNSServiceErrorType retval =
        dnssd->DNSServiceRegister(&dnssd->legacy_service, 0, 0,
                                  servname, "_raop._tcp",
                                  NULL, NULL,
                                  htons(port),
                                  dnssd->TXTRecordGetLength(&dnssd->legacy_record),
                                  dnssd->TXTRecordGetBytesPtr(&dnssd->legacy_record),
                                  NULL, NULL);
    return (int) retval;
}

void
dnssd_unregister_legacy(dnssd_t *dnssd)
{
    assert(dnssd);
    if (!dnssd->legacy_service) {
        return;
    }
    dnssd->DNSServiceRefDeallocate(dnssd->legacy_service);
    dnssd->legacy_service = NULL;
    dnssd->TXTRecordDeallocate(&dnssd->legacy_record);
}

int
dnssd_register_airplay(dnssd_t *dnssd, unsigned short port)
{
    char device_id[3 * MAX_HWADDR_LEN];
    char features[22] = {0};

    assert(dnssd);

    snprintf(features, sizeof(features), "0x%X,0x%X", dnssd->features1, dnssd->features2);

    /* Convert hardware address to string */
    if (utils_hwaddr_airplay(device_id, sizeof(device_id), dnssd->hw_addr, dnssd->hw_addr_len) < 0) {
        /* FIXME: handle better */
        return -1;
    }

    // flags is a string representing a 20-bit flag (up to 3 hex digits)
    dnssd->TXTRecordCreate(&dnssd->airplay_record, 0, NULL);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "deviceid", strlen(device_id), device_id);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "features", strlen(features), features);
    switch (dnssd->pin_pw) {
    case 1:   // display onscreen pin
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("true"), "true");
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;  
    case 2:  // require password
    case 3:
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("true"), "true");
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;
    default:
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "pw", strlen("false"), "false");
        dnssd->TXTRecordSetValue(&dnssd->airplay_record, "flags", 3, "0x4");
        break;
    }
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "model", strlen(GLOBAL_MODEL), GLOBAL_MODEL);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "pk", strlen(dnssd->pk), dnssd->pk);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "pi", strlen(AIRPLAY_PI), AIRPLAY_PI);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "srcvers", strlen(AIRPLAY_SRCVERS), AIRPLAY_SRCVERS);
    dnssd->TXTRecordSetValue(&dnssd->airplay_record, "vv", strlen(AIRPLAY_VV), AIRPLAY_VV);

    /* Register the service */
    DNSServiceErrorType retval = dnssd->DNSServiceRegister(&dnssd->airplay_service, 0, 0,
                                                           dnssd->name, "_airplay._tcp",
                                                           NULL, NULL,
                                                           htons(port),
                                                           dnssd->TXTRecordGetLength(&dnssd->airplay_record),
                                                           dnssd->TXTRecordGetBytesPtr(&dnssd->airplay_record),
                                                           NULL, NULL);

    return (int) retval;   /* error codes are listed in Apple's dns_sd.h */
}

const char *
dnssd_get_raop_txt(dnssd_t *dnssd, int *length)
{
    *length = dnssd->TXTRecordGetLength(&dnssd->raop_record);
    return dnssd->TXTRecordGetBytesPtr(&dnssd->raop_record);
}

const char *
dnssd_get_airplay_txt(dnssd_t *dnssd, int *length)
{
    *length = dnssd->TXTRecordGetLength(&dnssd->airplay_record);
    return dnssd->TXTRecordGetBytesPtr(&dnssd->airplay_record);
}

const char *
dnssd_get_name(dnssd_t *dnssd, int *length)
{
    *length = dnssd->name_len;
    return dnssd->name;
}

const char *
dnssd_get_hw_addr(dnssd_t *dnssd, int *length)
{
    *length = dnssd->hw_addr_len;
    return dnssd->hw_addr;
}

void
dnssd_unregister_raop(dnssd_t *dnssd)
{
    assert(dnssd);

    if (!dnssd->raop_service) {
        return;
    }

    /* Deallocate TXT record */
    dnssd->TXTRecordDeallocate(&dnssd->raop_record);

    dnssd->DNSServiceRefDeallocate(dnssd->raop_service);
    dnssd->raop_service = NULL;

    if (dnssd->airplay_service == NULL) {
        free(dnssd->name);
        free(dnssd->hw_addr);
    }
}

void
dnssd_unregister_airplay(dnssd_t *dnssd)
{
    assert(dnssd);

    if (!dnssd->airplay_service) {
        return;
    }

    /* Deallocate TXT record */
    dnssd->TXTRecordDeallocate(&dnssd->airplay_record);

    dnssd->DNSServiceRefDeallocate(dnssd->airplay_service);
    dnssd->airplay_service = NULL;

    if (dnssd->raop_service == NULL) {
        free(dnssd->name);
        free(dnssd->hw_addr);
    }
}

uint64_t dnssd_get_airplay_features(dnssd_t *dnssd) {
    uint64_t features = ((uint64_t) dnssd->features2) << 32;
    features += (uint64_t) dnssd->features1;
    return features;
}

void dnssd_set_pk(dnssd_t *dnssd, char * pk_str) {
    dnssd->pk = pk_str;
}

void dnssd_set_airplay_features(dnssd_t *dnssd, int bit, int val) {
    uint32_t mask = 0;
    uint32_t *features = 0;
    if (bit < 0 || bit > 63) return;
    if (val < 0 || val > 1) return;
    if (bit >= 32) {
        mask = 0x1 << (bit - 32);
        features = &(dnssd->features2);
    } else {
        mask = 0x1 << bit;
        features = &(dnssd->features1);
    }
    if (val) {
        *features = *features | mask;
    } else {
        *features = *features & ~mask;
    }
}
