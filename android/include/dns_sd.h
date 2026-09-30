/*
 * The slice of Apple's dns_sd API that UxPlay's dnssd.c uses, for Android.
 *
 * Android has no libdns_sd for an app to link. Advertising is done by the
 * platform's NsdManager instead, reached through hooks the JNI layer installs
 * (see dns_sd_android.c); this header only has to give dnssd.c the types and
 * functions it expects. TXTRecordRef is ours rather than Apple's opaque union,
 * since every function that touches it is implemented here too.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef UXPLAY_ANDROID_DNS_SD_H
#define UXPLAY_ANDROID_DNS_SD_H

#include <stdint.h>

#define DNSSD_STDCALL

typedef struct _DNSServiceRef_t *DNSServiceRef;
typedef uint32_t DNSServiceFlags;
typedef int32_t DNSServiceErrorType;

enum {
    kDNSServiceErr_NoError = 0,
    kDNSServiceErr_Unknown = -65537,
    kDNSServiceErr_NoMemory = -65539,
    kDNSServiceErr_BadParam = -65540,
    kDNSServiceErr_ServiceNotRunning = -65563,
};

typedef void (DNSSD_STDCALL *DNSServiceRegisterReply)(DNSServiceRef sdRef, DNSServiceFlags flags,
                                                      DNSServiceErrorType errorCode,
                                                      const char *name, const char *regtype,
                                                      const char *domain, void *context);

typedef struct {
    uint8_t *buf;
    uint16_t len;
    uint16_t cap;
    int owned;
} TXTRecordRef;

DNSServiceErrorType DNSServiceRegister(DNSServiceRef *sdRef, DNSServiceFlags flags,
                                       uint32_t interfaceIndex, const char *name,
                                       const char *regtype, const char *domain, const char *host,
                                       uint16_t port, uint16_t txtLen, const void *txtRecord,
                                       DNSServiceRegisterReply callBack, void *context);
void DNSServiceRefDeallocate(DNSServiceRef sdRef);

void TXTRecordCreate(TXTRecordRef *txtRecord, uint16_t bufferLen, void *buffer);
void TXTRecordDeallocate(TXTRecordRef *txtRecord);
DNSServiceErrorType TXTRecordSetValue(TXTRecordRef *txtRecord, const char *key, uint8_t valueSize,
                                      const void *value);
uint16_t TXTRecordGetLength(const TXTRecordRef *txtRecord);
const void *TXTRecordGetBytesPtr(const TXTRecordRef *txtRecord);

/*
 * Installed by the JNI layer. register returns a positive id for the
 * registration, or a negative dns_sd error; port is in host byte order and txt
 * is the raw TXT rdata (length-prefixed "key=value" strings).
 */
typedef int (*uxplay_dnssd_register_fn)(const char *name, const char *regtype, uint16_t port,
                                        const uint8_t *txt, uint16_t txt_len);
typedef void (*uxplay_dnssd_unregister_fn)(int id);
void uxplay_dnssd_set_hooks(uxplay_dnssd_register_fn reg, uxplay_dnssd_unregister_fn unreg);

#endif
