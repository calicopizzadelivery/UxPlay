/*
 * dns_sd for UxPlay on Android: TXT records built here, registration handed to
 * the platform's NsdManager through hooks set by the JNI layer.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "dns_sd.h"

struct _DNSServiceRef_t {
    int id;
};

static pthread_mutex_t hook_lock = PTHREAD_MUTEX_INITIALIZER;
static uxplay_dnssd_register_fn register_hook;
static uxplay_dnssd_unregister_fn unregister_hook;

void uxplay_dnssd_set_hooks(uxplay_dnssd_register_fn reg, uxplay_dnssd_unregister_fn unreg) {
    pthread_mutex_lock(&hook_lock);
    register_hook = reg;
    unregister_hook = unreg;
    pthread_mutex_unlock(&hook_lock);
}

DNSServiceErrorType DNSServiceRegister(DNSServiceRef *sdRef, DNSServiceFlags flags,
                                       uint32_t interfaceIndex, const char *name,
                                       const char *regtype, const char *domain, const char *host,
                                       uint16_t port, uint16_t txtLen, const void *txtRecord,
                                       DNSServiceRegisterReply callBack, void *context) {
    (void)flags; (void)interfaceIndex; (void)domain; (void)host; (void)callBack; (void)context;
    if (sdRef == NULL || name == NULL || regtype == NULL)
        return kDNSServiceErr_BadParam;
    pthread_mutex_lock(&hook_lock);
    uxplay_dnssd_register_fn reg = register_hook;
    pthread_mutex_unlock(&hook_lock);
    if (reg == NULL)
        return kDNSServiceErr_ServiceNotRunning;
    /* dns_sd takes the port in network byte order. */
    int id = reg(name, regtype, ntohs(port), txtRecord, txtLen);
    if (id <= 0)
        return id < 0 ? id : kDNSServiceErr_Unknown;
    struct _DNSServiceRef_t *ref = malloc(sizeof(*ref));
    if (ref == NULL)
        return kDNSServiceErr_NoMemory;
    ref->id = id;
    *sdRef = ref;
    return kDNSServiceErr_NoError;
}

void DNSServiceRefDeallocate(DNSServiceRef sdRef) {
    if (sdRef == NULL)
        return;
    pthread_mutex_lock(&hook_lock);
    uxplay_dnssd_unregister_fn unreg = unregister_hook;
    pthread_mutex_unlock(&hook_lock);
    if (unreg != NULL)
        unreg(sdRef->id);
    free(sdRef);
}

/* TXT rdata: a run of length-prefixed strings, "key=value" or bare "key". */

void TXTRecordCreate(TXTRecordRef *txt, uint16_t bufferLen, void *buffer) {
    txt->buf = buffer;
    txt->len = 0;
    txt->cap = buffer ? bufferLen : 0;
    txt->owned = buffer == NULL;
}

void TXTRecordDeallocate(TXTRecordRef *txt) {
    if (txt->owned)
        free(txt->buf);
    txt->buf = NULL;
    txt->len = txt->cap = 0;
}

static void remove_key(TXTRecordRef *txt, const char *key) {
    size_t klen = strlen(key);
    uint16_t off = 0;
    while (off < txt->len) {
        uint8_t n = txt->buf[off];
        const uint8_t *s = txt->buf + off + 1;
        if (n >= klen && memcmp(s, key, klen) == 0 && (n == klen || s[klen] == '=')) {
            memmove(txt->buf + off, txt->buf + off + 1 + n, txt->len - off - 1 - n);
            txt->len -= 1 + n;
            return;
        }
        off += 1 + n;
    }
}

DNSServiceErrorType TXTRecordSetValue(TXTRecordRef *txt, const char *key, uint8_t valueSize,
                                      const void *value) {
    size_t klen = strlen(key);
    size_t entry = klen + (value ? 1 + valueSize : 0);
    if (klen == 0 || entry > 255)
        return kDNSServiceErr_BadParam;
    remove_key(txt, key);
    if ((size_t)txt->len + 1 + entry > txt->cap) {
        if (!txt->owned)
            return kDNSServiceErr_NoMemory;
        size_t cap = (txt->len + 1 + entry) * 2;
        if (cap > 65535)
            cap = 65535;
        if ((size_t)txt->len + 1 + entry > cap)
            return kDNSServiceErr_NoMemory;
        uint8_t *grown = realloc(txt->buf, cap);
        if (grown == NULL)
            return kDNSServiceErr_NoMemory;
        txt->buf = grown;
        txt->cap = (uint16_t)cap;
    }
    uint8_t *p = txt->buf + txt->len;
    *p++ = (uint8_t)entry;
    memcpy(p, key, klen);
    p += klen;
    if (value) {
        *p++ = '=';
        memcpy(p, value, valueSize);
    }
    txt->len += 1 + entry;
    return kDNSServiceErr_NoError;
}

uint16_t TXTRecordGetLength(const TXTRecordRef *txt) { return txt->len; }

const void *TXTRecordGetBytesPtr(const TXTRecordRef *txt) { return txt->buf; }
