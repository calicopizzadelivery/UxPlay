/**  Copyright (C) 2011-2012  Juho Vähä-Herttua
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
 *===================================================================
 * modified by fduncanh 2021-23
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "raop.h"
#include "raop_rtp.h"
#include "pairing.h"
#include "httpd.h"

#include "global.h"
#include "fairplay.h"
#include "netutils.h"
#include "logger.h"
#include "compat.h"
#include "raop_rtp_mirror.h"
#include "raop_ntp.h"


/* libplist-2.3.0  API change */
#ifndef PLIST_230
static void plist_mem_free(void *ptr) {
    if (ptr) {
        free (ptr);
    }
}
#endif

struct raop_s {
    /* Callbacks for audio and video */
    raop_callbacks_t callbacks;

    /* Logger instance */
    logger_t *logger;

    /* Pairing, HTTP daemon and RSA key */
    pairing_t *pairing;
    httpd_t *httpd;

    dnssd_t *dnssd;

    /* local network ports */  
    unsigned short port;
    unsigned short timing_lport;
    unsigned short control_lport;
    unsigned short data_lport;
    unsigned short mirror_data_lport;  

    /* configurable plist items: width, height, refreshRate, maxFPS, overscanned *
     * also clientFPSdata, which controls whether video stream info received     *
     * from the client is shown on terminal monitor.                             */
    uint16_t width;
    uint16_t height;
    uint8_t refreshRate;
    uint8_t maxFPS;
    uint8_t overscanned;
    uint8_t clientFPSdata;

    int audio_delay_micros;

     /* for temporary storage of pin during pair-pin start */
    unsigned short pin;
    bool use_pin;
    /* Let an UNPAIRED sender play audio, but never mirror. macOS Apple Music
       opens with fp-setup and never pairs, so without this the box cannot be
       used as a speaker at all while the pin is on. ON by default: the
       exposure is bounded by the LAN -- AirPlay here has no Bluetooth or AWDL
       transport, so a sender must already be on the network -- and losing the
       commonest use of the feature is the worse trade. The owner can turn it
       off to require the code for audio as well. See docs/airplay.md. */
    bool open_audio;
    /* when a random pin shown by pair-pin-start stops being accepted */
    uint64_t pin_expiry;
    /* Guesses left against the code now on screen. Counts rejected proofs,
       not step-1s: a client that starts and wanders off costs nothing, and
       this is the only point where a mistype is distinguishable. */
    int pin_attempts;
    /* Bumped whenever a new code is rolled. A connection records the value
       it armed its SRP verifier under, and step 2 refuses a mismatch, so the
       budget bounds comparisons rather than arms -- without this an armed
       verifier could be re-driven for more guesses than the budget allows. */
    unsigned int pin_generation;
  
     /* public key as string */
    char pk_str[2*ED25519_KEY_SIZE + 1];

    /* place to store media_data_store */
    airplay_video_t *airplay_video[MAX_AIRPLAY_VIDEO];
    int current_video;
  
    /* activate support for HLS live streaming */
    bool hls_support;
    bool hls_pending;
  
    /* used in digest authentication */
    char *nonce;
    char *random_pw;
    unsigned char auth_fail_count;

  /* used for setting HLS video language choices */
    char *lang;
};

struct raop_conn_s {
    raop_t *raop;
    raop_ntp_t *raop_ntp;
    raop_rtp_t *raop_rtp;
    raop_rtp_mirror_t *raop_rtp_mirror;
    fairplay_t *fairplay;
    pairing_session_t *session;
  
    unsigned char *local;
    int locallen;

    unsigned char *remote;
    int remotelen;

    unsigned int zone_id;

    connection_type_t connection_type; 

    char *client_session_id;
    bool authenticated;
    bool have_active_remote;
    /* The pin generation this connection armed its SRP verifier under; see
       raop_t.pin_generation. 0 means it never completed step 1. */
    unsigned int pin_generation;

    /* Classic AirPlay 1 / RAOP. The session key and the stream parameters
       arrive in ANNOUNCE's SDP, one request before SETUP, where AirPlay 2
       carries them in SETUP's own plist. macOS drives every audio-only
       session this way -- Apple Music and Sound > Output alike -- so these
       hold what ANNOUNCE decoded until SETUP builds the session from them. */
    bool classic_raop;
    unsigned char classic_aeskey[16];
    unsigned char classic_aesiv[16];
    unsigned short classic_spf;
    unsigned int classic_sr;
    unsigned char classic_ct;
    bool classic_encrypted;

    /* In pin mode: this client proved the pin on this connection, or
       pair-verify found its key among the registered ones. */
    bool pin_verified;
};
typedef struct raop_conn_s raop_conn_t;

#include "raop_handlers.h"
#include "http_handlers.h"

static void *
conn_init(void *opaque, unsigned char *local, int locallen, unsigned char *remote, int remotelen, unsigned int zone_id) {
    raop_t *raop = opaque;
    raop_conn_t *conn = NULL;
    char ip_address[40] = { '\0' };
    assert(raop);

    conn = calloc(1, sizeof(raop_conn_t));
    if (!conn) {
        return NULL;
    }
    conn->raop = raop;
    conn->raop_rtp = NULL;
    conn->raop_rtp_mirror = NULL;
    conn->raop_ntp = NULL;
    conn->fairplay = fairplay_init(raop->logger);

    if (!conn->fairplay) {
        free(conn);
        return NULL;
    }
    conn->session = pairing_session_init(raop->pairing);
    if (!conn->session) {
        fairplay_destroy(conn->fairplay);
        free(conn);
        return NULL;
    }

    utils_ipaddress_to_string(locallen, local, zone_id, ip_address, (int) sizeof(ip_address));
    logger_log(raop->logger, LOGGER_INFO, "Local : %s", ip_address);

    utils_ipaddress_to_string(remotelen, remote, zone_id, ip_address, (int) sizeof(ip_address));
    logger_log(raop->logger, LOGGER_INFO, "Remote: %s", ip_address);

    conn->local = (unsigned char *) malloc(locallen);
    assert(conn->local);
    memcpy(conn->local, local, locallen);

    conn->remote = (unsigned char *) malloc(remotelen);
    assert(conn->remote);
    memcpy(conn->remote, remote, remotelen);

    conn->zone_id = zone_id;

    conn->locallen = locallen;
    conn->remotelen = remotelen;

    conn->connection_type = CONNECTION_TYPE_UNKNOWN;
    conn->client_session_id = NULL;

    conn->authenticated = false;

    conn->have_active_remote = false;
    
    if (raop->callbacks.conn_init) {
        raop->callbacks.conn_init(raop->callbacks.cls);
    }

    return conn;
}

static void
conn_request(void *ptr, http_request_t *request, http_response_t **response) {
    char *response_data = NULL;
    int response_datalen = 0;
    raop_conn_t *conn = ptr;
    raop_t *raop = conn->raop;
    bool hls_request = false;
    logger_log(raop->logger, LOGGER_DEBUG, "conn_request");
    bool logger_debug = (logger_get_level(raop->logger) >= LOGGER_DEBUG);
    bool logger_debug_data = (logger_get_level(raop->logger) >= LOGGER_DEBUG_DATA);

    /* 
    All requests arriving here have been parsed by llhttp to obtain 
    method | url | protocol (RTSP/1.0 or HTTP/1.1)

    There are four types of connections supplying these requests:
    Connections from the AirPlay client:
    (1) type RAOP connections with CSeq seqence  header, and no X-Apple-Session-ID header
    (2) type AIRPLAY connection with an X-Apple-Sequence-ID header and no Cseq header
    Connections from localhost:
    (3) type HLS internal connections from the local HLS server (gstreamer) at localhost with neither 
        of these headers,  but a Host: localhost:[port] header.   method = GET.
    (4) a special RAOP connection trigggered by a Bluetooth LE beacon: Protocol RTSP/1.0, method: GET
        url /info?txtAirPlay?txtRAOP, and no headers including CSeq
     */

    const char *method = http_request_get_method(request);
    const char *url = http_request_get_url(request);
    const char *protocol = http_request_get_protocol(request);

    if (!method  || !url || !protocol) {
        return;
    }

#define MAX_HDR_FIELDS 20
#define MAX_HDR_FIELD_LEN 64
#define MAX_HDR_VALUE_LEN 1024
    /*impose limits on header sizes to defend against DOS attacks */
    size_t max_field_len, max_value_len;
    int num_fields;
    http_request_header_get_size(request, &num_fields, &max_field_len, &max_value_len);
    if (num_fields > MAX_HDR_FIELDS || max_field_len > MAX_HDR_FIELD_LEN || max_value_len > MAX_HDR_VALUE_LEN) {
        logger_log(raop->logger, LOGGER_ERR, "rejecting request with overlong headers: %d fields,"
                   "max field_name length %d, max field value length %d",
                   num_fields, (int) max_field_len, (int) max_value_len);
        *response = http_response_create();
        http_response_init(*response, protocol, 431, "Request Header Fields Too Large");
        return;
    }

    /* handle CSeq header carefully, as it will be included in response: value should be non-negative int */
    char *cseq = NULL;
    char cseq_buf[11] = {0};
    const char *cseq_req = http_request_get_header(request, "CSeq");
    if (cseq_req) {
        int cseq_val = parse_int(cseq_req);
        if (cseq_val < 0) {
            logger_log(raop->logger, LOGGER_ERR, "rejecting request with invalid CSeq value %s", cseq_req);
            return;   //CSeq header field had invalid value
        }
        snprintf(cseq_buf, sizeof(cseq_buf), "%u", (unsigned int) cseq_val);
        cseq = cseq_buf;
    }

    /* ¨identify if request is a response to a BLE beacon */    
    bool ble = false;
    if (!strcmp(protocol,"RTSP/1.0") && !cseq  && (strstr(url, "txtAirPlay") || strstr(url, "txtRAOP") )) {
        logger_log(raop->logger, LOGGER_INFO, "response to Bluetooth LE beacon advertisement received)");
        ble = true;
    }

 /* this rejects messages from _airplay._tcp for video streaming protocol unless bool raop->hls_support is true*/
    if (!cseq && !raop->hls_support && !ble) {
        logger_log(raop->logger, LOGGER_INFO, "ignoring AirPlay video streaming request (use option -hls to activate HLS support)");
        return;
    }

    /* RAIL 24. The gate above is skipped by anything carrying a CSeq header,
       which is every RTSP request -- so a sender that simply set CSeq walked
       into the AirPlay-video handler table even with hls_support off. The
       video handlers are reached by their own URLs, so refuse those outright
       when HLS is not enabled, independently of CSeq. The six callbacks they
       use also have stubs now (see raop_init), so this is the outer of two
       defences rather than the only one. */
    if (!raop->hls_support && !ble && url) {
        static const char *video_urls[] = {
            "/play", "/scrub", "/rate", "/stop", "/playback-info",
            "/action", "/getProperty", "/setProperty",
        };
        for (size_t i = 0; i < sizeof(video_urls) / sizeof(video_urls[0]); i++) {
            size_t n = strlen(video_urls[i]);
            if (!strncmp(url, video_urls[i], n) && (url[n] == '\0' || url[n] == '?')) {
                logger_log(raop->logger, LOGGER_INFO,
                           "refusing AirPlay video request %s: HLS support is not enabled", url);
                http_response_init(*response, protocol, 403, "Forbidden");
                goto finish;
            }
        }
    }

    const char *client_session_id = http_request_get_header(request, "X-Apple-Session-ID");
    const char *host = http_request_get_header(request, "Host");
    hls_request =  (host && !cseq && !client_session_id);

    if (conn->connection_type == CONNECTION_TYPE_UNKNOWN) {
        if (cseq || ble) {
            if (httpd_count_connection_type(raop->httpd, CONNECTION_TYPE_RAOP)) {
                char ipaddr[40] = { '\0' };
                utils_ipaddress_to_string(conn->remotelen, conn->remote, conn->zone_id, ipaddr, (int) (sizeof(ipaddr)));

                /* RAIL 25. Displacing whoever is watching is a big thing to do
                   on behalf of an unauthenticated stranger, and it used to
                   happen on ANY request carrying a CSeq header -- a bare
                   OPTIONS from anyone on the LAN ended the owner's session.

                   A new sender still takes the television, which is the
                   intended behaviour for a shared screen, but only on a
                   request that actually begins a session. Every real sender
                   opens with one of these; a prober does not. The residual is
                   that a determined device on the LAN can still displace by
                   sending a real pairing request, which cannot be closed here:
                   the eviction happens on first contact, before any
                   authentication could have taken place. */
                bool starts_session =
                    !strcmp(method, "ANNOUNCE") || !strcmp(method, "SETUP") ||
                    (!strcmp(method, "POST") && url &&
                     (strstr(url, "/pair-setup") || strstr(url, "/pair-verify") ||
                      strstr(url, "/pair-pin-start") || strstr(url, "/fp-setup")));
                if (!starts_session) {
                    logger_log(raop->logger, LOGGER_INFO,
                               "%s %s from %s while another client is connected:"
                               " answering, but not taking the session",
                               method, url ? url : "", ipaddr);
                } else if (httpd_nohold(raop->httpd)) {
                    logger_log(raop->logger, LOGGER_INFO, "*****\"nohold\" feature: switch to new connection request from %s", ipaddr);		  
                    httpd_remove_known_connections(raop->httpd);
                    if (raop->callbacks.video_reset) {
                        raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_NOHOLD);
                    }
                } else {
                    logger_log(raop->logger, LOGGER_WARNING, "rejecting new connection request from %s", ipaddr);
                    *response = http_response_create();
                    http_response_init(*response, protocol, 409, "Conflict: Server is connected to another client");
                    goto finish;
                }
            }
            logger_log(raop->logger, LOGGER_DEBUG, "New connection %p identified as Connection type RAOP", ptr);
            httpd_set_connection_type(raop->httpd, ptr, CONNECTION_TYPE_RAOP);
            conn->connection_type = CONNECTION_TYPE_RAOP;
        } else if (client_session_id) {
            logger_log(raop->logger, LOGGER_DEBUG, "New connection %p identified as Connection type AirPlay", ptr);            
            httpd_set_connection_type(raop->httpd, ptr, CONNECTION_TYPE_AIRPLAY);
            conn->connection_type = CONNECTION_TYPE_AIRPLAY;
            /* RAIL 15. assert() is a no-op here -- -DNDEBUG is a Soong global --
               so a failed allocation fell straight through to a NULL memcpy.
               The header is attacker-supplied and unbounded in length, which
               is what makes the allocation worth failing gracefully. */
            size_t session_id_len = strlen(client_session_id);
            conn->client_session_id = (char *) calloc(session_id_len + 1, sizeof(char));
            if (!conn->client_session_id) {
                logger_log(raop->logger, LOGGER_ERR,
                           "could not allocate %zu bytes for X-Apple-Session-ID", session_id_len + 1);
                *response = http_response_create();
                http_response_init(*response, protocol, 500, "Internal Server Error");
                goto finish;
            }
            memcpy(conn->client_session_id, client_session_id, session_id_len);
            /* airplay video has been requested: shut down any running RAOP udp services */
            raop_conn_t *raop_conn = (raop_conn_t *) httpd_get_connection_by_type(raop->httpd, CONNECTION_TYPE_RAOP, 1);
            if (raop_conn) {
                raop_rtp_mirror_t *raop_rtp_mirror = raop_conn->raop_rtp_mirror;
                if (raop_rtp_mirror) {
                    logger_log(raop->logger, LOGGER_DEBUG, "New AirPlay connection: stopping RAOP mirror"
                               " service on RAOP connection %p", raop_conn);
                    raop_rtp_mirror_stop(raop_rtp_mirror);
                }

                raop_rtp_t *raop_rtp = raop_conn->raop_rtp;
                if (raop_rtp) {
                    logger_log(raop->logger, LOGGER_DEBUG, "New AirPlay connection: stopping RAOP audio"
                               " service on RAOP connection %p", raop_conn);
                    raop_rtp_stop(raop_rtp);
                }

                raop_ntp_t *raop_ntp = raop_conn->raop_ntp;
                if (raop_rtp) {
                    logger_log(raop->logger, LOGGER_DEBUG, "New AirPlay connection: stopping NTP time"
                               " service on RAOP connection %p", raop_conn);
                    raop_ntp_stop(raop_ntp);
                }
            }
        } else if (host) {
            logger_log(raop->logger, LOGGER_DEBUG, "New connection %p identified as Connection type HLS", ptr);            
            httpd_set_connection_type(raop->httpd, ptr, CONNECTION_TYPE_HLS);
            conn->connection_type = CONNECTION_TYPE_HLS;
        } else {
            logger_log(raop->logger, LOGGER_WARNING, "connection from unknown connection type");
        }	  
    }

    /* this response code and message  will be modified by the handler if necessary */
    *response = http_response_create();
    http_response_init(*response, protocol, 200, "OK");

    /* is this really necessary? or is it obsolete? (added for all RTSP requests EXCEPT "RECORD") */
    if (cseq && strcmp(method, "RECORD")) {
	    http_response_add_header(*response, "Audio-Jack-Status", "connected; type=digital");
    }

    if (!conn->have_active_remote) {
        const char *active_remote = http_request_get_header(request, "Active-Remote");
        if (active_remote) {
            conn->have_active_remote = true;
            if (raop->callbacks.export_dacp) {
                const char *dacp_id = http_request_get_header(request, "DACP-ID");
                raop->callbacks.export_dacp(raop->callbacks.cls, active_remote, dacp_id);
            }
        }
    }

    logger_log(raop->logger, LOGGER_DEBUG, "\n%s %s %s", method, url, protocol);
    if (!strcmp(url,"/playback-info")) {
        logger_debug = logger_debug_data;
    }
    char *header_str= NULL; 
    http_request_get_header_string(request, &header_str);
    if (header_str && logger_debug) {
        logger_log(raop->logger, LOGGER_DEBUG, "%s", header_str);
        bool data_is_plist = (strstr(header_str,"apple-binary-plist") != NULL);
        bool data_is_text = (strstr(header_str,"text/") != NULL);
        int request_datalen = 0;
        const char *request_data = http_request_get_data(request, &request_datalen);
        if (request_data) {
            if (request_datalen > 0) {
                /* logger has a buffer limit of 4096 */
                if (data_is_plist) {
                    plist_t req_root_node = NULL;
                    plist_from_bin(request_data, request_datalen, &req_root_node);
                    char * plist_xml = NULL;
                    char * stripped_xml = NULL;
                    uint32_t plist_len = 0;
                    plist_to_xml(req_root_node, &plist_xml, &plist_len);
                    stripped_xml = utils_strip_data_from_plist_xml(plist_xml);
                    logger_log(raop->logger, LOGGER_DEBUG, "%s", (stripped_xml ? stripped_xml : plist_xml));
                    if (stripped_xml) {
                        free(stripped_xml);
                    }
                    if (plist_xml) {
                        plist_mem_free(plist_xml);
                    }
                    plist_free(req_root_node);
                } else if (data_is_text) {
                    char *data_str = utils_data_to_text((char *) request_data, request_datalen);
                    logger_log(raop->logger, LOGGER_DEBUG, "%s", data_str);                    
                    free(data_str);
                } else {
                    char *data_str =  utils_data_to_string((unsigned char *) request_data, request_datalen, 16);
                    logger_log(raop->logger, LOGGER_DEBUG, "%s", data_str);
                    free(data_str);
                }
            }
        }
    }
    if (header_str) {
        free(header_str);
    }
    
    if (client_session_id) {
        assert(!strcmp(client_session_id, conn->client_session_id));
    }

    logger_log(raop->logger, LOGGER_DEBUG, "Handling request %s with URL %s", method, url);
    raop_handler_t handler = NULL;
    if (!hls_request && !strcmp(protocol, "RTSP/1.0")) {
        if (!strcmp(method, "POST")) {
            if (!strcmp(url, "/feedback")) {
                handler = &raop_handler_feedback;
            } else if (!strcmp(url, "/pair-pin-start")) {
                handler = &raop_handler_pairpinstart;
            } else if (!strcmp(url, "/pair-setup-pin")) {
                handler = &raop_handler_pairsetup_pin;
            } else if (!strcmp(url, "/pair-setup")) {
                handler = &raop_handler_pairsetup;
            } else if (!strcmp(url, "/pair-verify")) {
                handler = &raop_handler_pairverify;
            } else if (!strcmp(url, "/fp-setup")) {
                handler = &raop_handler_fpsetup;
            } else if (!strcmp(url, "/audioMode")) {
                handler = &raop_handler_audiomode;
            }
        } else if (!strcmp(method, "GET")) {
            if (strstr(url, "/info")) {
                handler = &raop_handler_info;
            }
        } else if (!strcmp(method, "OPTIONS")) {
            handler = &raop_handler_options;
        } else if (!strcmp(method, "ANNOUNCE")) {
            handler = &raop_handler_announce;
        } else if (!strcmp(method, "SETUP")) {
            raop->hls_pending = false;
            handler = &raop_handler_setup;
        } else if (!strcmp(method, "GET_PARAMETER")) {
            handler = &raop_handler_get_parameter;
        } else if (!strcmp(method, "SET_PARAMETER")) {
            handler = &raop_handler_set_parameter;
        } else if (!strcmp(method, "RECORD")) {
            handler = &raop_handler_record;
        } else if (!strcmp(method, "FLUSH")) {
            handler = &raop_handler_flush;
        } else if (!strcmp(method, "TEARDOWN")) {
            handler = &raop_handler_teardown;
        } else {
            http_response_init(*response, protocol, 501, "Not Implemented");
        }
    } else if (!hls_request && !strcmp(protocol, "HTTP/1.1")) {
        if (!strcmp(method, "POST")) {
            if (!strcmp(url, "/reverse")) {
                handler = &http_handler_reverse;
            } else if (!strcmp(url, "/play")) {
                handler = &http_handler_play;
            } else if (!strncmp (url, "/getProperty?", strlen("/getProperty?"))) {
                handler = &http_handler_get_property;
            } else if (!strncmp(url, "/scrub?", strlen("/scrub?"))) {
                handler = &http_handler_scrub;
            } else if (!strncmp(url, "/rate?", strlen("/rate?"))) {
                handler = &http_handler_rate;
            } else if (!strcmp(url, "/stop")) {
                handler = &http_handler_stop;
            } else if (!strcmp(url, "/action")) {
                handler = &http_handler_action;
            } else if (!strcmp(url, "/fp-setup2")) {
                handler = &http_handler_fpsetup2;
            }
        } else if (!strcmp(method, "GET")) {
            if (!strcmp(url, "/server-info")) {
                raop->hls_pending = true;
                handler = &http_handler_server_info;
            } else if (!strcmp(url, "/playback-info")) {
                handler = &http_handler_playback_info;
            }
        } else if (!strcmp(method, "PUT")) {
            if (!strncmp (url, "/setProperty?", strlen("/setProperty?"))) {
                handler = &http_handler_set_property;
            }
        }
    } else if (hls_request) {
        handler = &http_handler_hls;
    }

    if (handler != NULL) {
        handler(conn, request, *response, &response_data, &response_datalen);
    } else {
        logger_log(raop->logger, LOGGER_INFO,
                   "Unhandled Client Request: %s %s %s", method, url, protocol);
    }

    finish:;
    if (!hls_request) {
        /* A legacy sender identifies itself by carrying Apple-Challenge, and
           expects a classic AirTunes version: shairport-sync answers
           "AirTunes/105.1" in its classic build (rtsp.c:4219) and macOS talks
           to it. Our GLOBAL_VERSION is an AirPlay 2 era string, which on the
           legacy service is as much an AirPlay 2 marker as "pk" in the TXT
           record. AirPlay 2 senders keep the modern one. */
        const char *server_version =
            http_request_get_header(request, "Apple-Challenge")
                ? "AirTunes/105.1" : "AirTunes/"GLOBAL_VERSION;
        http_response_add_header(*response, "Server", server_version);
        if (cseq) {
            http_response_add_header(*response, "CSeq", cseq);
        }
        /* Classic RAOP challenge-response. A legacy sender puts an
           Apple-Challenge on its requests and expects an Apple-Response
           signed with the AirPort Express private key; without one a Mac
           closes the connection straight after OPTIONS and reports the
           receiver as incompatible. shairport-sync answers it on every RTSP
           request (rtsp.c:4209), so do the same rather than only on OPTIONS. */
        raop_apple_challenge(conn, request, *response);
    }
    http_response_finish(*response, response_data, response_datalen);
    int len = 0;
    const char *data = http_response_get_data(*response, &len);
    if (response_data && response_datalen > 0) {
        len -= response_datalen;
    } else {
        len -= 2;
    }
    header_str =  utils_data_to_text(data, len);
    bool data_is_plist = (strstr(header_str,"apple-binary-plist") != NULL);
    bool data_is_text = (strstr(header_str,"text/") != NULL ||
                         strstr(header_str, "x-mpegURL") != NULL);

    if (!logger_debug) {
        char *ptr = strchr(header_str, '\n');
        *(++ptr) = '\0';
    }
    logger_log(raop->logger, LOGGER_DEBUG, "%s", header_str);
    free(header_str);
    if (response_data) {
        if (response_datalen > 0 && logger_debug) {
            /* logger has a buffer limit of 4096 */
            if (data_is_plist) {
                plist_t res_root_node = NULL;
                plist_from_bin(response_data, response_datalen, &res_root_node);
                char * plist_xml = NULL;
                char * stripped_xml = NULL;
                uint32_t plist_len;
                plist_to_xml(res_root_node, &plist_xml, &plist_len);
                stripped_xml = utils_strip_data_from_plist_xml(plist_xml);
                logger_log(raop->logger, LOGGER_DEBUG, "%s", (stripped_xml ? stripped_xml : plist_xml));
                if (stripped_xml) {
                    free(stripped_xml);
                }
                if (plist_xml) {
                    plist_mem_free(plist_xml);
                }
                plist_free(res_root_node);
            } else if (data_is_text) {
                char *data_str = utils_data_to_text((char*) response_data, response_datalen);
                logger_log(raop->logger, LOGGER_DEBUG, "%s", data_str);                    
                free(data_str);
            } else {
                char *data_str = utils_data_to_string((unsigned char *) response_data, response_datalen, 16);
                logger_log(raop->logger, LOGGER_DEBUG, "%s", data_str);
                free(data_str);
            }
        }
        if (response_data) {
            free(response_data);
        }
    }
}

static void
conn_destroy(void *ptr) {
    raop_conn_t *conn = ptr;
    raop_t *raop = conn->raop;
    logger_log(raop->logger, LOGGER_DEBUG, "Destroying connection");

    if (raop->callbacks.conn_destroy) {
        raop->callbacks.conn_destroy(raop->callbacks.cls);
    }

    if (conn->raop_rtp) {
        /* This is done in case TEARDOWN was not called */
        raop_rtp_destroy(conn->raop_rtp);
    }
    if (conn->raop_rtp_mirror) {
        /* This is done in case TEARDOWN was not called */
        raop_rtp_mirror_destroy(conn->raop_rtp_mirror);
    }
    if (conn->raop_ntp) {
        raop_ntp_destroy(conn->raop_ntp);
    }

    if (raop->callbacks.video_flush) {
        raop->callbacks.video_flush(raop->callbacks.cls);
    }

    free(conn->local);
    free(conn->remote);
    pairing_session_destroy(conn->session);
    fairplay_destroy(conn->fairplay);
    if (conn->client_session_id) {
        free(conn->client_session_id);
    }

    free(conn);
}


/* ---------------------------------------------------------------------------
   Default no-op callbacks for the AirPlay-video / HLS handlers.

   raop_init copies the caller's struct verbatim, so any callback an embedder
   leaves unset stays NULL and is then called unconditionally from
   lib/http_handlers.h -- seven call sites, none of them guarded. The Android
   embedder assigns 27 callbacks and not these six, because it implements no
   HLS player, which made every one of them a one-request crash reachable from
   any device on the LAN. RAIL 24.

   Stubs rather than call-site null checks: a check has to be remembered at
   every future call site, a default cannot be forgotten. The playback-info
   stub reports "finished", which is the value that makes the HLS handler
   unwind cleanly rather than wait.
   --------------------------------------------------------------------------- */
static void noop_video_play(void *cls, const char *location, const float start_position) {
    (void) cls; (void) location; (void) start_position;
}
static void noop_video_scrub(void *cls, const float position) { (void) cls; (void) position; }
static void noop_video_rate(void *cls, const float rate) { (void) cls; (void) rate; }
static void noop_video_stop(void *cls) { (void) cls; }
static void noop_video_acquire_playback_info(void *cls, playback_info_t *playback_info) {
    (void) cls;
    if (playback_info) {
        memset(playback_info, 0, sizeof(*playback_info));
        playback_info->duration = -1.0f;   /* "finished": the handler resets */
    }
}
static float noop_video_playlist_remove(void *cls) { (void) cls; return 0.0f; }


raop_t *
raop_init(raop_callbacks_t *callbacks) {
    assert(callbacks);

    /* Initialize the network */
    if (netutils_init() < 0) {
        return NULL;
    }

    /* Validate the callbacks structure */
    if (!callbacks->audio_process ||
        !callbacks->video_process) {
        return NULL;
    }

    /* Allocate the raop_t structure */
    raop_t *raop = (raop_t *) calloc(1, sizeof(raop_t));
    if (!raop) {
        return NULL;
    }

    /* Initialize the logger */
    raop->logger = logger_init();

    /* Copy callbacks structure */
    memcpy(&raop->callbacks, callbacks, sizeof(raop_callbacks_t));

    /* Anything the embedder left unset gets a stub, so an unauthenticated
       request cannot reach a NULL function pointer. See the block above. */
    if (!raop->callbacks.on_video_play) raop->callbacks.on_video_play = noop_video_play;
    if (!raop->callbacks.on_video_scrub) raop->callbacks.on_video_scrub = noop_video_scrub;
    if (!raop->callbacks.on_video_rate) raop->callbacks.on_video_rate = noop_video_rate;
    if (!raop->callbacks.on_video_stop) raop->callbacks.on_video_stop = noop_video_stop;
    if (!raop->callbacks.on_video_acquire_playback_info)
        raop->callbacks.on_video_acquire_playback_info = noop_video_acquire_playback_info;
    if (!raop->callbacks.on_video_playlist_remove)
        raop->callbacks.on_video_playlist_remove = noop_video_playlist_remove;

    /* initialize network port list */ 
    raop->port = 0;    
    raop->timing_lport = 0;
    raop->control_lport = 0;
    raop->data_lport = 0;
    raop->mirror_data_lport = 0;

    /* initialize configurable plist parameters */
    raop->width = 1920;
    raop->height = 1080;
    raop->refreshRate = 60;
    raop->maxFPS = 30;
    raop->overscanned = 0;

    /* initialise stored pin */
    raop->pin = 0;
    raop->use_pin = false;
    raop->pin_attempts = 0;
    raop->pin_generation = 0;
    raop->open_audio = true;

    /* initialize switch for display of client's streaming data records */    
    raop->clientFPSdata = 0;

    /* initialize airplay_video */
    raop->current_video = -1;
    for (int i= 0; i < MAX_AIRPLAY_VIDEO; i++) {
        raop->airplay_video[i] = NULL;
    }

    raop->audio_delay_micros = 250000;

    raop->hls_support = false;
    raop->hls_pending = false;
    
    raop->nonce = NULL;

    raop->lang = NULL;
    return raop;
}

int
raop_init2(raop_t *raop, int nohold, const char *device_id, const char *keyfile) {
    pairing_t *pairing = NULL;
    httpd_t *httpd = NULL;

    /* create a new public key for pairing */
    int new_key = 0;
    pairing = pairing_init_generate(device_id, keyfile, &new_key);
    if (!pairing) {
        logger_log(raop->logger, LOGGER_ERR, "failed to create new public key for pairing");
        return -1;
    }
    /* store PK as a string in raop->pk_str */
    memset(raop->pk_str, 0, sizeof(raop->pk_str));
#ifdef PK
    strncpy(raop->pk_str, PK, 2*ED25519_KEY_SIZE);
#else
    unsigned char public_key[ED25519_KEY_SIZE] = { '\0' };
    pairing_get_public_key(pairing, public_key);
    char *pk_str = utils_hex_to_string(public_key, ED25519_KEY_SIZE);
    strncpy(raop->pk_str, (const char *) pk_str, 2*ED25519_KEY_SIZE);
    free(pk_str);
#endif
    if (new_key) {
        logger_log(raop->logger, LOGGER_INFO,"*** A new Public Key has been created and stored in %s", keyfile);
    }

    /* Set HTTP callbacks to our handlers */
    httpd_callbacks_t httpd_cbs;
    memset(&httpd_cbs, 0, sizeof(httpd_cbs));
    httpd_cbs.opaque = raop;
    httpd_cbs.conn_init = &conn_init;
    httpd_cbs.conn_request = &conn_request;
    httpd_cbs.conn_destroy = &conn_destroy;

    /* Initialize the http daemon, (this will take a copy of httpd_cbs) */
    httpd = httpd_init(raop->logger, &httpd_cbs, nohold);
    if (!httpd) {
        logger_log(raop->logger, LOGGER_ERR, "failed to initialize http daemon");
        pairing_destroy(pairing);
        return -1;
    }

    raop->pairing = pairing;
    raop->httpd = httpd;
    return 0;
}

void
raop_destroy(raop_t *raop) {
    if (raop) {
        raop_destroy_airplay_video(raop, -1);
        raop_stop_httpd(raop);
        pairing_destroy(raop->pairing);
        httpd_destroy(raop->httpd);
        logger_destroy(raop->logger);
        if (raop->nonce) {
            free(raop->nonce);
        }
        if (raop->random_pw) {
            free(raop->random_pw);
        }

        if (raop->lang) {
            free(raop->lang);
        }

        free(raop);

        /* Cleanup the network */
        netutils_cleanup();
    }
}

int
raop_is_running(raop_t *raop) {
    assert(raop);

    return httpd_is_running(raop->httpd);
}

void
raop_set_log_level(raop_t *raop, int level) {
    assert(raop);

    logger_set_level(raop->logger, level);
}

int raop_set_plist(raop_t *raop, const char *plist_item, const int value) {
    int retval = 0;
    assert(raop);
    assert(plist_item);
    
    if (strcmp(plist_item, "width") == 0) {
        raop->width = (uint16_t) value;
        if ((int) raop->width != value) retval = 1;
    } else if (strcmp(plist_item, "height") == 0) {
        raop->height = (uint16_t) value;
        if ((int) raop->height != value) retval = 1;
    } else if (strcmp(plist_item, "refreshRate") == 0) {
        raop->refreshRate = (uint8_t) value;
        if ((int) raop->refreshRate != value) retval = 1;
    } else if (strcmp(plist_item, "maxFPS") == 0) {
        raop->maxFPS = (uint8_t) value;
        if ((int) raop->maxFPS != value) retval = 1;
    } else if (strcmp(plist_item, "overscanned") == 0) {
        raop->overscanned = (uint8_t) (value ? 1 : 0);
        if ((int) raop->overscanned  != value) retval = 1;
    } else if (strcmp(plist_item, "clientFPSdata") == 0) {
        raop->clientFPSdata = (value ? 1 : 0);
        if ((int) raop->clientFPSdata  != value) retval = 1;
    } else if (strcmp(plist_item, "audio_delay_micros") == 0) {
        if (value >= 0 && value <= 10 * SECOND_IN_USECS) {     
            raop->audio_delay_micros = value;
        }
        if (raop->audio_delay_micros != value) retval = 1;
    } else if (strcmp(plist_item, "open_audio") == 0) {
        raop->open_audio = (value != 0);
    } else if (strcmp(plist_item, "pin") == 0) {
        raop->pin = value;
        raop->use_pin = true;
    } else if (strcmp(plist_item, "hls") == 0) {
        raop->hls_support = (value > 0 ? true : false);
    } else {
        retval = -1;
    }	  
    return retval;
}

void
raop_set_port(raop_t *raop, unsigned short port) {
    assert(raop);
    raop->port = port;
}

void
raop_set_udp_ports(raop_t *raop, unsigned short udp[3]) {
    assert(raop);
    raop->timing_lport = udp[0]; 
    raop->control_lport = udp[1];
    raop->data_lport = udp[2];
}

void
raop_set_tcp_ports(raop_t *raop, unsigned short tcp[2]) {
    assert(raop);
    raop->mirror_data_lport = tcp[0];
    raop->port = tcp[1];
}

unsigned short
raop_get_port(raop_t *raop) {
    assert(raop);
    return raop->port;
}

void *
raop_get_callback_cls(raop_t *raop) {
    assert(raop);
    return raop->callbacks.cls;
}

void
raop_set_log_callback(raop_t *raop, raop_log_callback_t callback, void *cls) {
    assert(raop);

    logger_set_callback(raop->logger, callback, cls);
}

void
raop_set_dnssd(raop_t *raop, dnssd_t *dnssd) {
    assert(dnssd);
    dnssd_set_pk(dnssd, raop->pk_str);
    raop->dnssd = dnssd;
}

void
raop_set_lang(raop_t *raop, const char *lang) {
    if (raop->lang) {
        free (raop->lang);
        raop->lang = NULL;
    }
    if (lang && strlen(lang)) {
        raop->lang = (char *) calloc(strlen(lang) + 1, sizeof(char));
        memcpy(raop->lang, lang, strlen(lang));
    }
}

char *
raop_get_lang(raop_t *raop) {
    return raop->lang;
}

int
raop_start_httpd(raop_t *raop, unsigned short *port) {
    assert(raop);
    assert(port);
    return httpd_start(raop->httpd, port);
}

void
raop_stop_httpd(raop_t *raop) {
    assert(raop);
    httpd_stop(raop->httpd);
}

void raop_remove_known_connections(raop_t * raop) {
    httpd_remove_known_connections(raop->httpd);
}

void raop_remove_hls_connections(raop_t * raop) {
    httpd_remove_connections_by_type(raop->httpd, CONNECTION_TYPE_HLS);
    httpd_remove_connections_by_type(raop->httpd, CONNECTION_TYPE_PTTH);
    httpd_remove_connections_by_type(raop->httpd, CONNECTION_TYPE_AIRPLAY);
}

void raop_destroy_airplay_video(raop_t *raop, int id) {
    assert (id < MAX_AIRPLAY_VIDEO);
    for (int i = 0; i < MAX_AIRPLAY_VIDEO; i++) {
        if (id >= 0 && id != i) {
            continue;
        }
        if (raop->airplay_video[i]) {
            airplay_video_destroy(raop->airplay_video[i]);
            raop->airplay_video[i] = NULL;
            if (i == raop->current_video) {
                raop->current_video = -1;
            }
        }
    }
}

void raop_handle_eos(raop_t *raop) {
    int id = raop->current_video;
    assert (id >= 0);
    raop_destroy_airplay_video(raop, id);
    raop->current_video = -1;
    /* reset video without deleting raop->airplay_video */
    raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_HLS_EOS);
}

uint64_t get_local_time() {
    return raop_ntp_get_local_time();
}
