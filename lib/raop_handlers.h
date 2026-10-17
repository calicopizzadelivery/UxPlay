/**
 *  Copyright (C) 2018  Juho Vähä-Herttua
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
 * modfied by fduncanh 2021-2023
 */

/* This file should be only included from raop.c as it defines static handler
 * functions and depends on raop internals */

#include "dnssdint.h"
#include "utils.h"
#include "crypto.h"   /* rsa_aeskey_decrypt, for classic RAOP */
#include <ctype.h>
#include <stdlib.h>
#include <inttypes.h>
#include <plist/plist.h>
#include <time.h>

/* How long a pin shown by pair-pin-start stays valid: long enough to walk
   to the phone and type it, short enough that an old one is not left open. */
#define PIN_LIFETIME_NS (120ULL * 1000000000ULL)

static uint64_t pin_clock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}
#define AUDIO_SAMPLE_RATE 44100   /* all supported AirPlay audio format use this sample rate */
#define SECOND_IN_USECS 1000000
#define SECOND_IN_NSECS 1000000000
#define MAX_PW_ATTEMPTS 3

/* Guesses allowed against one displayed code. A four-digit code read off a
   television and typed on a phone is mistyped often, and before this a single
   slip retired the code with no way back.

   Four, not three, because the sender spends one by itself. A device that was
   paired before still holds the old password, so when the receiver forgets it
   the sender submits that saved one the instant a code appears -- measured at
   108 ms after PAIR-PIN-START, long before anyone could read four digits off
   a screen -- and only prompts the person once it is refused. Three therefore
   gave a human two, and exactly in the situation where someone is most likely
   to be re-pairing. Four gives a human three.

   The cost is small and was computed rather than assumed: with random_pin()'s
   modulo bias the best single guess is 7/65529, so per displayed code this
   moves 1 in 3,120 to 1 in 2,340. It does not change guesses per second at
   all, because a rejected proof releases the SRP state and every guess needs
   its own step 1 regardless of the budget.

   The budget bounds guesses per code; it does not bound codes. pair-pin-start
   is unauthenticated and unthrottled, so an attacker on the LAN can roll fresh
   codes without limit -- see docs/airplay.md, "The PIN gate". This is a
   usability fix with a bounded cost, not the thing that makes pairing safe. */
#define MAX_PIN_ATTEMPTS 4

typedef void (*raop_handler_t)(raop_conn_t *, http_request_t *,
                               http_response_t *, char **, int *);


static void
raop_handler_info(raop_conn_t *conn,
                  http_request_t *request, http_response_t *response,
                  char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    assert(raop->dnssd);

    /* There are three possible RTSP/1.0  GET/info requests
       (1) with a CSeq number and with a plist
       (2) with a CSeq number and without a plist
       (3) without a CSeq number or a Header (part of Bluetooth LE Service Discovery) */

    const char* url =  NULL;
    const char* content_type =  NULL;
    const char* cseq =  NULL;
    url  = http_request_get_url(request);
    content_type = http_request_get_header(request, "Content-Type");
    cseq = http_request_get_header(request, "CSeq");
    int len = 0;
    bool add_txt_airplay = false;
    bool add_txt_raop = false;
    const char txtRAOP[] = "txtRAOP";
    const char txtAirPlay[] = "txtAirPlay";


    plist_t res_node = plist_new_dict();
     
    /* initial GET/info request sends plist with string "txtAirPlay" */
    if (content_type && strstr(content_type, "application/x-apple-binary-plist")) {
        char *qualifier_string = NULL;
        const char *data = NULL;
        int data_len = 0;
        data = http_request_get_data(request, &data_len);
        //parsing bplist
        plist_t req_root_node = NULL;
        plist_from_bin(data, data_len, &req_root_node);
        plist_t req_qualifier_node = plist_dict_get_item(req_root_node, "qualifier");
        if (PLIST_IS_ARRAY(req_qualifier_node)) {
            plist_t req_string_node = plist_array_get_item(req_qualifier_node, 0);
            plist_get_string_val(req_string_node, &qualifier_string);
        }
        if (qualifier_string) {
            if (!strcmp(qualifier_string, txtAirPlay )) {
                add_txt_airplay = true;
            } else if (!strcmp(qualifier_string, txtRAOP)) {
                add_txt_raop = true;
            }
            plist_mem_free(qualifier_string);
        }
        plist_free(req_root_node);
    }
    

    /* Bluetoth LE discovery protocol request */
    if (!cseq) {
        add_txt_airplay = (bool) strstr(url, txtAirPlay);
        add_txt_raop = (bool) strstr(url, txtRAOP);
    }
    
    if (add_txt_airplay) {
        const char *txt = dnssd_get_airplay_txt(raop->dnssd, &len);
        plist_t txt_airplay_node = plist_new_data(txt, len);
        plist_dict_set_item(res_node, txtAirPlay, txt_airplay_node);
    }

    if (add_txt_raop) {
        const char *txt = dnssd_get_raop_txt(raop->dnssd, &len);
        plist_t txt_raop_node = plist_new_data(txt, len);
        plist_dict_set_item(res_node, txtRAOP, txt_raop_node);
    }
  
    /* don't need anything below here in the response to initial  "txtAirPlay" GET/info request */
    if (content_type) {
        goto finished;
    }
 
    /* deviceID is the physical hardware address, and will not change */
    int hw_addr_raw_len = 0;
    const char *hw_addr_raw = dnssd_get_hw_addr(raop->dnssd, &hw_addr_raw_len);
    char *hw_addr = calloc(1, 3 * hw_addr_raw_len);
    //int hw_addr_len =
    utils_hwaddr_airplay(hw_addr, 3 * hw_addr_raw_len, hw_addr_raw, hw_addr_raw_len);
    plist_t device_id_node = plist_new_string(hw_addr);
    plist_dict_set_item(res_node, "deviceID", device_id_node);

    plist_t mac_address_node = plist_new_string(hw_addr);
    plist_dict_set_item(res_node, "macAddress", mac_address_node);
    free(hw_addr);
   
    /* Persistent Public Key */
    int pk_len = 0;
    char *pk = utils_parse_hex(raop->pk_str, strlen(raop->pk_str), &pk_len);
    plist_t pk_node = plist_new_data(pk, pk_len);
    plist_dict_set_item(res_node, "pk", pk_node);
    free(pk);

    uint64_t features = dnssd_get_airplay_features(raop->dnssd);
    plist_t features_node = plist_new_uint(features);
    plist_dict_set_item(res_node, "features", features_node);

    int name_len = 0;
    const char *name = dnssd_get_name(raop->dnssd, &name_len);
    plist_t name_node = plist_new_string(name);
    plist_dict_set_item(res_node, "name", name_node);

    plist_t pi_node = plist_new_string(AIRPLAY_PI);
    plist_dict_set_item(res_node, "pi", pi_node);

    plist_t vv_node = plist_new_uint(strtol(AIRPLAY_VV, NULL, 10));
    plist_dict_set_item(res_node, "vv", vv_node);

    /* 68 is 0x44. Bit 3 (0x08) is "pin required", and a receiver that asks
       for a code has to say so here as well as in its mDNS TXT -- a sender
       reads whichever it reaches first, and the two disagreeing is worse than
       either being wrong. Upstream hard-codes 68 in every mode. */
    plist_t status_flags_node = plist_new_uint(conn->raop->use_pin ? 68 | 0x08 : 68);
    plist_dict_set_item(res_node, "statusFlags", status_flags_node);

    plist_t keep_alive_low_power_node = plist_new_uint(1);
    plist_dict_set_item(res_node, "keepAliveLowPower", keep_alive_low_power_node);

    plist_t source_version_node = plist_new_string(GLOBAL_VERSION);
    plist_dict_set_item(res_node, "sourceVersion", source_version_node);

    plist_t keep_alive_send_stats_as_body_node = plist_new_bool(1);
    plist_dict_set_item(res_node, "keepAliveSendStatsAsBody", keep_alive_send_stats_as_body_node);

    plist_t model_node = plist_new_string(GLOBAL_MODEL);
    plist_dict_set_item(res_node, "model", model_node);

    /* dont need anything below here in the Bluetooth LE response */
    if (cseq == NULL) {
        goto finished;
    }

    plist_t initial_volume_node = plist_new_real(raop->callbacks.audio_set_client_volume(raop->callbacks.cls)); 
    plist_dict_set_item(res_node, "initialVolume", initial_volume_node);
      
    plist_t audio_latencies_node = plist_new_array();
    plist_t audio_latencies_0_node = plist_new_dict();
    plist_t audio_latencies_0_output_latency_micros_node = plist_new_bool(0);
    plist_t audio_latencies_0_type_node = plist_new_uint(100);
    plist_t audio_latencies_0_audio_type_node = plist_new_string("default");
    plist_t audio_latencies_0_input_latency_micros_node = plist_new_uint(0);
    plist_dict_set_item(audio_latencies_0_node, "type", audio_latencies_0_type_node);
    plist_dict_set_item(audio_latencies_0_node, "inputLatencyMicros", audio_latencies_0_input_latency_micros_node);
    plist_dict_set_item(audio_latencies_0_node, "audioType", audio_latencies_0_audio_type_node);
    plist_dict_set_item(audio_latencies_0_node, "outputLatencyMicros", audio_latencies_0_output_latency_micros_node);
    plist_array_append_item(audio_latencies_node, audio_latencies_0_node);

    plist_t audio_latencies_1_node = plist_new_dict();
    plist_t audio_latencies_1_output_latency_micros_node = plist_new_bool(0);
    plist_t audio_latencies_1_type_node = plist_new_uint(101);
    plist_t audio_latencies_1_audio_type_node = plist_new_string("default");
    plist_t audio_latencies_1_input_latency_micros_node = plist_new_uint(0);
    plist_dict_set_item(audio_latencies_1_node, "type", audio_latencies_1_type_node);
    plist_dict_set_item(audio_latencies_1_node, "audioType", audio_latencies_1_audio_type_node);
    plist_dict_set_item(audio_latencies_1_node, "inputLatencyMicros", audio_latencies_1_input_latency_micros_node);
    plist_dict_set_item(audio_latencies_1_node, "outputLatencyMicros", audio_latencies_1_output_latency_micros_node);
    plist_array_append_item(audio_latencies_node, audio_latencies_1_node);
    plist_dict_set_item(res_node, "audioLatencies", audio_latencies_node);

    plist_t audio_formats_node = plist_new_array();
    plist_t audio_format_0_node = plist_new_dict();
    plist_t audio_format_0_type_node = plist_new_uint(100);
    plist_t audio_format_0_audio_input_formats_node = plist_new_uint(0x3fffffc);
    plist_t audio_format_0_audio_output_formats_node = plist_new_uint(0x3fffffc);
    plist_dict_set_item(audio_format_0_node, "audioOutputFormats", audio_format_0_audio_output_formats_node);
    plist_dict_set_item(audio_format_0_node, "type", audio_format_0_type_node);
    plist_dict_set_item(audio_format_0_node, "audioInputFormats", audio_format_0_audio_input_formats_node);
    plist_array_append_item(audio_formats_node, audio_format_0_node);

    plist_t audio_format_1_node = plist_new_dict();
    plist_t audio_format_1_type_node = plist_new_uint(101);
    plist_t audio_format_1_audio_input_formats_node = plist_new_uint(0x3fffffc);
    plist_t audio_format_1_audio_output_formats_node = plist_new_uint(0x3fffffc);
    plist_dict_set_item(audio_format_1_node, "audioOutputFormats", audio_format_1_audio_output_formats_node);
    plist_dict_set_item(audio_format_1_node, "type", audio_format_1_type_node);
    plist_dict_set_item(audio_format_1_node, "audioInputFormats", audio_format_1_audio_input_formats_node);
    plist_array_append_item(audio_formats_node, audio_format_1_node);
    plist_dict_set_item(res_node, "audioFormats", audio_formats_node);

    plist_t displays_node = plist_new_array();
    plist_t displays_0_node = plist_new_dict();
    plist_t displays_0_width_physical_node = plist_new_uint(0);
    plist_t displays_0_height_physical_node = plist_new_uint(0);
    plist_t displays_0_uuid_node = plist_new_string("e0ff8a27-6738-3d56-8a16-cc53aacee925");
    plist_t displays_0_width_node = plist_new_uint(raop->width);
    plist_t displays_0_height_node = plist_new_uint(raop->height);
    plist_t displays_0_width_pixels_node = plist_new_uint(raop->width);
    plist_t displays_0_height_pixels_node = plist_new_uint(raop->height);
    plist_t displays_0_rotation_node = plist_new_bool(0); /* set to true in AppleTV gen 3 (which has features bit 8  set */
    plist_t displays_0_refresh_rate_node = plist_new_real((double) 1.0 / raop->refreshRate);  /* set as real 0.166666  = 60hz in AppleTV gen 3 */
    plist_t displays_0_max_fps_node = plist_new_uint(raop->maxFPS);
    plist_t displays_0_overscanned_node = plist_new_bool(raop->overscanned);
    plist_t displays_0_features = plist_new_uint(14);

    plist_dict_set_item(displays_0_node, "uuid", displays_0_uuid_node);
    plist_dict_set_item(displays_0_node, "widthPhysical", displays_0_width_physical_node);
    plist_dict_set_item(displays_0_node, "heightPhysical", displays_0_height_physical_node);
    plist_dict_set_item(displays_0_node, "width", displays_0_width_node);
    plist_dict_set_item(displays_0_node, "height", displays_0_height_node);
    plist_dict_set_item(displays_0_node, "widthPixels", displays_0_width_pixels_node);
    plist_dict_set_item(displays_0_node, "heightPixels", displays_0_height_pixels_node);
    plist_dict_set_item(displays_0_node, "rotation", displays_0_rotation_node);    
    plist_dict_set_item(displays_0_node, "refreshRate", displays_0_refresh_rate_node);
    plist_dict_set_item(displays_0_node, "maxFPS", displays_0_max_fps_node);
    plist_dict_set_item(displays_0_node, "overscanned", displays_0_overscanned_node);
    plist_dict_set_item(displays_0_node, "features", displays_0_features);
    plist_array_append_item(displays_node, displays_0_node);
    plist_dict_set_item(res_node, "displays", displays_node);

 finished:
    plist_to_bin(res_node, response_data, (uint32_t *) response_datalen);
    plist_free(res_node);
    http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
}

static void
raop_handler_pairpinstart(raop_conn_t *conn,
                          http_request_t *request, http_response_t *response,
                          char **response_data, int *response_datalen) {
    raop_t *raop = conn->raop;
    logger_log(raop->logger, LOGGER_INFO, "client sent PAIR-PIN-START request");
    if (!raop->use_pin) {
        /* Nothing to pair for, and no reason to put a pin on the screen. */
        http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
        return;
    }
    raop->pin_expiry = pin_clock_ns() + PIN_LIFETIME_NS;
    int pin_4 = 0;
    if (raop->pin > 9999) {
        pin_4 = raop->pin % 10000;
    } else {
        pin_4 = random_pin();
        if (pin_4 < 0) {
            logger_log(raop->logger, LOGGER_ERR, "Failed to generate random pin");
        } else {
            raop->pin = (unsigned short) pin_4 % 10000;
            /* Only on the branch that actually rolls a code, and together
               with the generation bump, so no future edit can re-arm the
               budget over a code already on screen. A fixed pin set by
               raop_set_plist is not re-armed here. */
            raop->pin_attempts = MAX_PIN_ATTEMPTS;
            raop->pin_generation++;
        }
    }
    char pin[6] = { '\0' };
    snprintf(pin, 5, "%04u", pin_4);
    if (raop->callbacks.display_pin) {
         raop->callbacks.display_pin(raop->callbacks.cls, pin);
    }
    logger_log(raop->logger, LOGGER_INFO, "*** CLIENT MUST NOW ENTER PIN = \"%s\" AS AIRPLAY PASSWORD", pin);
}

static void
raop_handler_pairsetup_pin(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen) {
    raop_t *raop = conn->raop;
    const char *request_data = NULL;;
    int request_datalen = 0;
    bool data_is_plist = false;
    bool logger_debug = (logger_get_level(raop->logger) >= LOGGER_DEBUG);
    request_data = http_request_get_data(request, &request_datalen);
    logger_log(raop->logger, LOGGER_INFO, "client requested pair-setup-pin, datalen = %d", request_datalen);
    if (request_datalen > 0) {
        char *header_str= NULL; 
        http_request_get_header_string(request, &header_str);
        logger_log(raop->logger, LOGGER_INFO, "request header: %s", header_str);
        data_is_plist = (strstr(header_str,"apple-binary-plist") != NULL);
        free(header_str);
    }
    if (!data_is_plist) {
        logger_log(raop->logger, LOGGER_INFO, "did not receive expected plist from client, request_datalen = %d",
                  request_datalen);
        goto authentication_failed;
    }

    /* process the pair-setup-pin request */
    plist_t req_root_node = NULL;
    plist_from_bin(request_data, request_datalen, &req_root_node);
    plist_t req_method_node = plist_dict_get_item(req_root_node, "method");
    plist_t req_user_node = plist_dict_get_item(req_root_node, "user");
    plist_t req_pk_node = plist_dict_get_item(req_root_node, "pk");
    plist_t req_proof_node = plist_dict_get_item(req_root_node, "proof");
    plist_t req_epk_node = plist_dict_get_item(req_root_node, "epk");
    plist_t req_authtag_node = plist_dict_get_item(req_root_node, "authTag");
  
    if (PLIST_IS_STRING(req_method_node) && PLIST_IS_STRING(req_user_node)) {
        /* this is the initial pair-setup-pin request */
        const char *salt = NULL;
        char pin[6] = { '\0' };
        const char *pk = NULL;
        int len_pk = 0, len_salt = 0;
        char *method = NULL;
        char *user = NULL;
        plist_get_string_val(req_method_node, &method);
        if (strncmp(method, "pin", strlen (method))) {
            logger_log(raop->logger, LOGGER_ERR, "error, required method is \"pin\", client requested \"%s\"", method);
            free (method);
            plist_free (req_root_node);
            return;
        }
        plist_mem_free(method);
        method = NULL;
        plist_get_string_val(req_user_node, &user);
        logger_log(raop->logger, LOGGER_INFO, "pair-setup-pin:  device_id = %s", user);
        /* A random pin exists only between pair-pin-start and its first use.
           Without this check a client that never asked for one paired with
           "0000", which is what raop->pin % 10000 is when none is pending. */
        if (raop->pin < 10000 && (!raop->use_pin || raop->pin == 0
                                  || raop->pin_attempts <= 0
                                  || pin_clock_ns() > raop->pin_expiry)) {
            logger_log(raop->logger, LOGGER_ERR, "pair-setup-pin with no pin on screen: refused");
            raop->pin = 0;
            plist_mem_free(user);
            plist_free(req_root_node);
            goto authentication_failed;
        }
        snprintf(pin, 6, "%04u", raop->pin % 10000);
        /* The code is NOT retired here. This is step 1, the salt and public
           key exchange; the client's proof does not arrive until step 2, so
           retiring it here burned the code on every outcome and made a
           mistype unrecoverable. It is retired in exactly three places: a
           proof accepted (step 3), the budget spent, and the guard above. */
        conn->pin_generation = raop->pin_generation;
        int ret = srp_new_user(conn->session, raop->pairing, (const char *) user,
                               (const char *) pin, &salt, &len_salt, &pk, &len_pk);
        plist_mem_free(user);
        user = NULL;
        plist_free(req_root_node);
        if (ret < 0) {
            logger_log(raop->logger, LOGGER_ERR, "failed to create user, err = %d", ret);
            goto authentication_failed;
        }
        plist_t res_root_node = plist_new_dict();
        plist_t res_salt_node = plist_new_data(salt, len_salt);
        plist_t res_pk_node = plist_new_data(pk, len_pk);
        plist_dict_set_item(res_root_node, "pk", res_pk_node);	
        plist_dict_set_item(res_root_node, "salt", res_salt_node);
        plist_to_bin(res_root_node, response_data, (uint32_t*) response_datalen);
        plist_free(res_root_node);
        http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
        return;
    } else if (PLIST_IS_DATA(req_pk_node) && PLIST_IS_DATA(req_proof_node)) {
        /* this is the second part of pair-setup-pin request */
        char *client_pk = NULL;
        char *client_proof = NULL;
        unsigned char proof[64] = { '\0' };
        memset(proof, 0, sizeof(proof));
        uint64_t client_pk_len = 0;
        uint64_t client_proof_len = 0;
        plist_get_data_val(req_pk_node, &client_pk, &client_pk_len); 
        plist_get_data_val(req_proof_node, &client_proof, &client_proof_len);
        int proof_len = (int) sizeof(proof);
        /* Only a capacity bound here: the exact length is one SRP_SHA digest,
           which srp_validate_proof knows and this function does not. The copy
           below takes client_proof_len bytes, so it can neither overrun
           proof[] nor read past what libplist allocated. */
        if (client_proof_len > sizeof(proof)) {
            logger_log(raop->logger, LOGGER_ERR, "Client Authentication Failure (client_proof_len %d invalid)", (int) client_proof_len);
            free (client_proof);
            free (client_pk);
            plist_free(req_root_node);
            goto authentication_failed;
        }
        if (logger_debug) {
            char *str = utils_data_to_string((const unsigned char *) client_proof, client_proof_len, 20);
            logger_log(raop->logger, LOGGER_DEBUG, "client SRP6a proof <M> :\n%s", str);	    
            free (str);
        }
        memcpy(proof, client_proof, (size_t) client_proof_len);
        free (client_proof);
        /* The budget is enforced HERE, where the secret is compared, and not
           only at step 1 where the verifier is armed. Gating the arm alone
           would let one armed verifier be re-driven across connections for
           more guesses than the budget allows. */
        if (raop->use_pin && conn->pin_generation != raop->pin_generation) {
            logger_log(raop->logger, LOGGER_ERR,
                       "pair-setup-pin: proof offered against a retired code: refused");
            free (client_pk);
            plist_free(req_root_node);
            goto authentication_failed;
        }
        int ret = srp_validate_proof(conn->session, raop->pairing, (const unsigned char *) client_pk,
                                     (int) client_pk_len, proof, (int) client_proof_len, &proof_len);
        free (client_pk);
        plist_free(req_root_node);
        if (ret == -3) {
            logger_log(raop->logger, LOGGER_ERR, "Client Authentication Failure (client_proof_len %d invalid)", (int) client_proof_len);
            goto authentication_failed;
        }
        if (ret == -1 && raop->use_pin && raop->pin_attempts > 0) {
            /* -1 alone means a proof was compared and rejected: a real guess.
               -2 and -4 are a bad key length and "nothing was armed", neither
               of which is one, so they must not spend the budget. */
            raop->pin_attempts--;
            conn->pin_generation = 0;
            logger_log(raop->logger, LOGGER_ERR,
                       "pair-setup-pin: wrong code, %d attempt(s) left", raop->pin_attempts);
            if (raop->pin_attempts <= 0) {
                raop->pin = 0;   /* retired: the next client must ask again */
            }
            if (raop->callbacks.pin_rejected) {
                raop->callbacks.pin_rejected(raop->callbacks.cls, raop->pin_attempts);
            }
        }
        if (ret < 0) {
            logger_log(raop->logger, LOGGER_ERR, "Client Authentication Failure (client proof not validated)");
            goto authentication_failed;
        }
        if (logger_debug) {
	    char *str = utils_data_to_string((const unsigned char *) proof, proof_len, 20);
            logger_log(raop->logger, LOGGER_DEBUG, "server SRP6a proof <M1> :\n%s", str);
            free (str);
        }
        plist_t res_root_node = plist_new_dict();
        plist_t res_proof_node = plist_new_data((const char *) proof, proof_len);
        plist_dict_set_item(res_root_node, "proof", res_proof_node);	
        plist_to_bin(res_root_node, response_data, (uint32_t*) response_datalen);
        plist_free(res_root_node);
        http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
        return;
    } else if (PLIST_IS_DATA(req_epk_node) && PLIST_IS_DATA(req_authtag_node)) {
        /* this is the third part of pair-setup-pin request */
        char *client_epk = NULL;
        char *client_authtag = NULL;
        uint64_t client_epk_len = 0;
        uint64_t client_authtag_len = 0;
        unsigned char epk[ED25519_KEY_SIZE];
        unsigned char authtag[GCM_AUTHTAG_SIZE];
        int ret = 0;
        plist_get_data_val(req_epk_node, &client_epk, &client_epk_len); 
        plist_get_data_val(req_authtag_node, &client_authtag, &client_authtag_len);
        /* Fixed-size copies follow: refuse anything else. */
        if (client_epk_len != ED25519_KEY_SIZE || client_authtag_len != GCM_AUTHTAG_SIZE) {
            logger_log(raop->logger, LOGGER_ERR, "pair-setup-pin (step 3): epk of %d bytes, authTag of %d",
                       (int) client_epk_len, (int) client_authtag_len);
            free(client_authtag);
            free(client_epk);
            plist_free(req_root_node);
            goto authentication_failed;
        }

        if (logger_debug) {
            char *str = utils_data_to_string((const unsigned char *) client_epk, client_epk_len, 16);
            logger_log(raop->logger, LOGGER_DEBUG, "client_epk %d:\n%s\n", (int) client_epk_len, str);
            str = utils_data_to_string((const unsigned char *) client_authtag, client_authtag_len, 16);
            logger_log(raop->logger, LOGGER_DEBUG, "client_authtag  %d:\n%s\n", (int) client_authtag_len, str);
            free (str);
        }

        memcpy(epk, client_epk, ED25519_KEY_SIZE);
        memcpy(authtag, client_authtag, GCM_AUTHTAG_SIZE);
        free (client_authtag);
        free (client_epk);
        plist_free(req_root_node);
        ret = srp_confirm_pair_setup(conn->session, raop->pairing, epk, authtag);
        if (ret < 0) {
            logger_log(raop->logger, LOGGER_ERR, "pair-pin-setup (step 3): client authentication failed\n");
            goto authentication_failed;
        } else {
            logger_log(raop->logger, LOGGER_DEBUG, "pair-pin-setup success\n");
        }
        pairing_session_set_setup_status(conn->session);
        conn->pin_verified = true;
        /* Proved. Retire the code so it cannot be replayed, and disarm the
           budget: the next client must ask for a new one. */
        raop->pin = 0;
        raop->pin_attempts = 0;
        raop->pin_generation++;
        /* Remember it as soon as it has proved the pin, not only if it goes
           on to stream; SETUP registers it again with its name. */
        if (raop->callbacks.register_client) {
            char *client_device_id = NULL;
            char *client_pk = NULL;
            get_pairing_session_client_data(conn->session, &client_device_id, &client_pk);
            if (client_pk) {
                raop->callbacks.register_client(raop->callbacks.cls, client_device_id, client_pk, NULL);
                free(client_pk);
            }
        }
        plist_t res_root_node = plist_new_dict();
        plist_t res_epk_node = plist_new_data((const char *) epk, 32);
        plist_t res_authtag_node = plist_new_data((const char *) authtag, 16);
        plist_dict_set_item(res_root_node, "epk", res_epk_node);
        plist_dict_set_item(res_root_node, "authTag", res_authtag_node);	
        plist_to_bin(res_root_node, response_data, (uint32_t*) response_datalen);
        plist_free(res_root_node);
        http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
        return;
    }
 authentication_failed:;
    http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
}

static void
raop_handler_pairsetup(raop_conn_t *conn,
                       http_request_t *request, http_response_t *response,
                       char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    unsigned char public_key[ED25519_KEY_SIZE];
    //const char *data;
    int datalen = 0;

    //data =
    http_request_get_data(request, &datalen);
    if (raop->use_pin) {
        /* Pairing without the pin: in pin mode it would let pair-verify
           through without either the pin or a registration. */
        logger_log(raop->logger, LOGGER_ERR, "pair-setup without a pin refused: pin mode is on");
        http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
        return;
    }
    if (datalen != 32) {
        logger_log(raop->logger, LOGGER_ERR, "Invalid pair-setup data");
        return;
    }

    pairing_get_public_key(raop->pairing, public_key);
    pairing_session_set_setup_status(conn->session);

    *response_data = calloc(1, sizeof(public_key));
    if (*response_data) {
        http_response_add_header(response, "Content-Type", "application/octet-stream");
        memcpy(*response_data, public_key, sizeof(public_key));
        *response_datalen = sizeof(public_key);
    }
}

static void
raop_handler_pairverify(raop_conn_t *conn,
                        http_request_t *request, http_response_t *response,
                        char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    bool register_check = false;  
    if (pairing_session_check_handshake_status(conn->session)) {
        if (raop->use_pin) {
            pairing_session_set_setup_status(conn->session);
            register_check = true;
            /* Standing comes from this check alone, whatever came before. */
            conn->pin_verified = false;
        } else {
            return;
        }
    }
    unsigned char public_key[X25519_KEY_SIZE];
    unsigned char signature[PAIRING_SIG_SIZE];
    const unsigned char *data = NULL;
    int datalen = 0;

    data = (unsigned char *) http_request_get_data(request, &datalen);
    if (datalen < 4) {
        logger_log(raop->logger, LOGGER_ERR, "Invalid pair-verify data");
        return;
    }
    switch (data[0]) {
    case 1:
        if (datalen != 4 + X25519_KEY_SIZE + ED25519_KEY_SIZE) {
            logger_log(raop->logger, LOGGER_ERR, "Invalid pair-verify data");
            return;
        }
        /* We can fall through these errors, the result will just be garbage... */
        if (pairing_session_handshake(conn->session, data + 4, data + 4 + X25519_KEY_SIZE)) {
            logger_log(raop->logger, LOGGER_ERR, "Error initializing pair-verify handshake");
        }
        if (pairing_session_get_public_key(conn->session, public_key)) {
            logger_log(raop->logger, LOGGER_ERR, "Error getting ECDH public key");
        }
        if (pairing_session_get_signature(conn->session, signature)) {
            logger_log(raop->logger, LOGGER_ERR, "Error getting ED25519 signature");
        }
        if (register_check) {
            /* No register to check means nobody is registered. */
            bool registered_client = false;
            if (raop->callbacks.check_register) {
                const unsigned char *pk = data + 4 + X25519_KEY_SIZE;
                char *pk64 = NULL;
                ed25519_pk_to_base64(pk, &pk64);
                registered_client = raop->callbacks.check_register(raop->callbacks.cls, pk64);
                free (pk64);
            }

            if (!registered_client) {
                http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
                return;
            }
            conn->pin_verified = true;
        }
        *response_data = calloc(1, sizeof(public_key) + sizeof(signature));
        if (*response_data) {
            http_response_add_header(response, "Content-Type", "application/octet-stream");
            memcpy(*response_data, public_key, sizeof(public_key));
            memcpy(*response_data + sizeof(public_key), signature, sizeof(signature));
            *response_datalen = sizeof(public_key) + sizeof(signature);
        }
        break;
    case 0:
        logger_log(raop->logger, LOGGER_DEBUG, "2nd pair-verify step: checking signature");
        if (datalen != 4 + PAIRING_SIG_SIZE) {
            logger_log(raop->logger, LOGGER_ERR, "Invalid pair-verify data");
            return;
        }

        if (pairing_session_finish(conn->session, data + 4)) {
            logger_log(raop->logger, LOGGER_ERR, "Incorrect pair-verify signature");
            http_response_set_disconnect(response, 1);
            return;
        }
        logger_log(raop->logger, LOGGER_DEBUG, "pair-verify: signature is verified");	    
        http_response_add_header(response, "Content-Type", "application/octet-stream");
        break;
    }
}

/* In pin mode nothing past pairing is served to a client that has not
   paired: proved the pin on this connection, or been found registered, and
   then completed pair-verify. UxPlay's own pin mode only asked honest
   clients to pair; a client could skip it and go straight to SETUP. */
/** True when this connection has proved the pin on this connection. */
static bool
pin_proved(raop_conn_t *conn)
{
    return conn->pin_verified && pairing_session_is_verified(conn->session);
}

static bool
pin_gate(raop_conn_t *conn, http_response_t *response, const char *what)
{
    raop_t *raop = conn->raop;
    if (!raop->use_pin || pin_proved(conn)) {
        return true;
    }
    if (raop->open_audio) {
        /* Deferred, not waived. An unpaired sender is let past fp-setup and
           the front of SETUP so that an audio-only client -- macOS Apple
           Music opens with fp-setup and never pairs -- can get as far as
           declaring what it wants. The mirroring stream type is refused
           inside the streams loop, which is the first point at which the
           request says which it is.

           What that costs is real and is not only audio: an unpaired device
           also reaches the FairPlay key exchange and the RTP and NTP setup
           that precede the loop, and can push metadata, artwork and volume.
           It cannot mirror.

           On by default, which was the user's call: the exposure is bounded
           by the LAN, because AirPlay here has no Bluetooth and no AWDL
           transport, and a television that silently refuses Apple Music is
           the worse failure. "Allow audio without a code" in Settings >
           System > AirPlay turns it off for anyone who disagrees. */
        return true;
    }
    logger_log(raop->logger, LOGGER_ERR, "%s refused: the client has not paired with the pin", what);
    http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
    return false;
}

static void
raop_handler_fpsetup(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;  
    const unsigned char *data = NULL;
    int datalen = 0;

    if (!pin_gate(conn, response, "fp-setup")) {
        return;
    }

    data = (unsigned char *) http_request_get_data(request, &datalen);
    logger_log(raop->logger, LOGGER_INFO, "fp-setup: %d bytes, type 0x%02x",
               datalen, datalen >= 5 ? data[4] : 0);
    if (datalen == 16) {
        *response_data = calloc(142, sizeof(char));
        if (*response_data) {
            http_response_add_header(response, "Content-Type", "application/octet-stream");
            if (!fairplay_setup(conn->fairplay, data, (unsigned char *) *response_data)) {
                *response_datalen = 142;
            } else {
                /* An empty body here is what the sender sees, and it reports
                   it as an incompatible receiver. fairplay_setup says why. */
                logger_log(raop->logger, LOGGER_ERR, "fp-setup stage 1 failed, answering empty");
                free(*response_data);
                *response_data = NULL;
            }
        }
    } else if (datalen == 164) {
        *response_data = calloc(32, sizeof(char));
        if (*response_data) {
            http_response_add_header(response, "Content-Type", "application/octet-stream");
            if (!fairplay_handshake(conn->fairplay, data, (unsigned char *) *response_data)) {
                *response_datalen = 32;
            } else {
                logger_log(raop->logger, LOGGER_ERR, "fp-setup stage 2 failed, answering empty");
                free(*response_data);
                *response_data = NULL;
            }
        }
    } else {
        logger_log(raop->logger, LOGGER_ERR, "Invalid fp-setup data length");
        return;
    }
}

static void
raop_handler_options(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen)
{
    http_response_add_header(response, "Public", "ANNOUNCE, SETUP, RECORD, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER");
}

/* ---------------------------------------------------------------------------
   Classic AirPlay 1 / RAOP.

   macOS drives every audio-only session this way -- Apple Music's AirPlay menu
   and Sound > Output alike -- while using AirPlay 2 for mirroring from the same
   machine. The shapes differ completely: AirPlay 2 carries the session key and
   the stream parameters in SETUP's own binary plist, where classic RAOP sends
   SDP in an ANNOUNCE first and then a SETUP whose parameters are in a
   "Transport:" request header with no body at all.

   What it does NOT need, which is the whole reason this is implementable:
   macOS sends "a=fpaeskey", a 72-byte FairPlay-wrapped key that
   fairplay_decrypt() already takes, on a connection that has just completed
   both fp-setup stages. shairport-sync parses "a=rsaaeskey" instead and needs
   Apple's leaked AirPort Express private RSA key to unwrap it; we need no RSA
   at all, and no Apple-Challenge either -- macOS sends none. Verified on the
   wire 2026-10-17; see docs/airplay.md.

   Classic RAOP has no mirroring stream, so a session on this path is audio by
   construction rather than by the sender's say-so. That is why it sits behind
   the same pin_gate as everything else and needs no separate refusal.
   --------------------------------------------------------------------------- */

/** Decode base64 into out, returning the byte count, or -1 on anything
    unexpected. SDP carries base64 unpadded, so '=' is tolerated but not
    required, and any other stray character is a refusal rather than a guess:
    this is network data from an unauthenticated sender. */
static int
raop_base64_decode(const char *in, int in_len, unsigned char *out, int out_max)
{
    static const signed char T[256] = {
        ['A']= 0,['B']= 1,['C']= 2,['D']= 3,['E']= 4,['F']= 5,['G']= 6,['H']= 7,
        ['I']= 8,['J']= 9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    };
    int nbits = 0, out_len = 0;
    uint32_t acc = 0;

    for (int i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char) in[i];
        if (c == '=') {
            break;
        }
        /* T['A'] is 0 and so is every unmapped slot, so 'A' needs its own test */
        if (T[c] == 0 && c != 'A') {
            return -1;
        }
        acc = (acc << 6) | (uint32_t) T[c];
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (out_len >= out_max) {
                return -1;
            }
            out[out_len++] = (unsigned char) ((acc >> nbits) & 0xff);
        }
    }
    return out_len;
}

/** Point at the value of SDP attribute "a=<name>:", and give its length.
    Returns NULL when absent. Only matches at the start of a line, so an
    attribute name appearing inside another attribute's value cannot match. */
static const char *
sdp_attribute(const char *sdp, int sdp_len, const char *name, int *value_len)
{
    int name_len = (int) strlen(name);
    for (int i = 0; i + 2 + name_len < sdp_len; i++) {
        if (sdp[i] != 'a' || sdp[i + 1] != '=') {
            continue;
        }
        if (i && sdp[i - 1] != '\n' && sdp[i - 1] != '\r') {
            continue;
        }
        if (strncmp(sdp + i + 2, name, (size_t) name_len) != 0 ||
            sdp[i + 2 + name_len] != ':') {
            continue;
        }
        const char *val = sdp + i + 2 + name_len + 1;
        const char *end = val;
        const char *limit = sdp + sdp_len;
        while (end < limit && *end != '\r' && *end != '\n') {
            end++;
        }
        *value_len = (int) (end - val);
        return val;
    }
    return NULL;
}

static void
raop_handler_announce(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;

    if (!pin_gate(conn, response, "ANNOUNCE")) {
        return;
    }

    /* Disarm first. Every refusal below must leave the connection unable to
       SETUP, or a sender could follow a rejected ANNOUNCE with a bodyless
       SETUP and get a session built from whatever the last good ANNOUNCE
       left behind. Everything is parsed into locals and committed in one
       block at the end for the same reason. */
    conn->classic_raop = false;

    int sdp_len = 0;
    const char *sdp = http_request_get_data(request, &sdp_len);
    if (!sdp || sdp_len <= 0) {
        logger_log(raop->logger, LOGGER_ERR, "ANNOUNCE with no SDP body");
        http_response_init(response, "RTSP/1.0", 400, "Bad Request");
        return;
    }

    /* Three shapes are possible, and which one arrives is decided by the "et"
       record we advertise (dnssdint.h) and by what the sender supports:
         a=rsaaeskey  encrypted to the AirPort Express public key -- RSA, et=1
         a=fpaeskey   FairPlay-wrapped -- et=3 or 5
         neither      encryption type 0, the stream is in clear -- et=0
       macOS only ever offers the first two, and its FairPlay key message is
       version 0x02, which lib/playfair cannot unwrap. So RSA is the path that
       works; see lib/rsakey.c. */
    int val_len = 0;
    bool encrypted = true;
    bool rsa = false;
    const char *val = sdp_attribute(sdp, sdp_len, "rsaaeskey", &val_len);
    if (val) {
        rsa = true;
    } else {
        val = sdp_attribute(sdp, sdp_len, "fpaeskey", &val_len);
    }
    if (!val) {
        int iv_probe = 0;
        if (sdp_attribute(sdp, sdp_len, "aesiv", &iv_probe)) {
            logger_log(raop->logger, LOGGER_ERR,
                       "ANNOUNCE has a=aesiv but no key attribute");
            http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
            return;
        }
        /* No key and no iv: encryption type 0. shairport has the same branch
           (rtsp.c:3563-3565). macOS has never taken it on this bench. */
        logger_log(raop->logger, LOGGER_INFO, "ANNOUNCE: unencrypted session");
        encrypted = false;
    }

    unsigned char aeskey[16] = { 0 };
    unsigned char aesiv[16] = { 0 };

    if (encrypted) {
        /* RSA ciphertext is one modulus block (256 bytes for RSA-2048);
           FairPlay's is a fixed 72. */
        unsigned char ekey[512] = { 0 };
        int ekey_len = raop_base64_decode(val, val_len, ekey, (int) sizeof(ekey));
        if (ekey_len <= 0) {
            logger_log(raop->logger, LOGGER_ERR, "ANNOUNCE: undecodable key attribute");
            http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
            return;
        }

        if (rsa) {
            int n = rsa_aeskey_decrypt(ekey, ekey_len, aeskey, (int) sizeof(aeskey));
            if (n == -2) {
                logger_log(raop->logger, LOGGER_ERR,
                           "ANNOUNCE: a=rsaaeskey needs the AirPort Express private key,"
                           " which this build does not carry -- see lib/rsakey.c");
                http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
                return;
            }
            if (n != (int) sizeof(aeskey)) {
                logger_log(raop->logger, LOGGER_ERR,
                           "ANNOUNCE a=rsaaeskey unwrapped to %d bytes, expected %zu",
                           n, sizeof(aeskey));
                http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
                return;
            }
        } else {
            /* fairplay_decrypt refuses unless fairplay_handshake ran on this
               connection (keymsglen == 164) AND the key message was version
               0x03. macOS sends 0x02, which playfair cannot unwrap. */
            if (ekey_len != 72) {
                logger_log(raop->logger, LOGGER_ERR,
                           "ANNOUNCE a=fpaeskey decoded to %d bytes, expected 72", ekey_len);
                http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
                return;
            }
            if (fairplay_decrypt(conn->fairplay, ekey, aeskey) < 0) {
                logger_log(raop->logger, LOGGER_ERR,
                           "ANNOUNCE: could not unwrap the session key");
                http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
                return;
            }
        }

        val = sdp_attribute(sdp, sdp_len, "aesiv", &val_len);
        int iv_len = val ? raop_base64_decode(val, val_len, aesiv, (int) sizeof(aesiv)) : -1;
        if (iv_len != (int) sizeof(aesiv)) {
            logger_log(raop->logger, LOGGER_ERR,
                       "ANNOUNCE a=aesiv decoded to %d bytes, expected %zu", iv_len, sizeof(aesiv));
            http_response_init(response, "RTSP/1.0", 456, "Header Field Not Valid for Resource");
            return;
        }
    }

    /* a=rtpmap:96 AppleLossless -- the only codec this path offers. The
       uncompressed "L16/44100/2" form shairport also accepts is not wired to
       our renderers, so refuse it rather than render noise. */
    char rtpmap[64] = { 0 };
    val = sdp_attribute(sdp, sdp_len, "rtpmap", &val_len);
    if (val && val_len > 0) {
        /* the SDP body is not NUL-terminated, so copy before any str* call */
        int n = val_len < (int) sizeof(rtpmap) - 1 ? val_len : (int) sizeof(rtpmap) - 1;
        memcpy(rtpmap, val, (size_t) n);
    }
    if (!strstr(rtpmap, "AppleLossless")) {
        logger_log(raop->logger, LOGGER_ERR,
                   "ANNOUNCE a=rtpmap is not AppleLossless: \"%s\"", rtpmap);
        http_response_init(response, "RTSP/1.0", 415, "Unsupported Media Type");
        return;
    }

    /* a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100
       Twelve ALAC parameters. We act on frames-per-packet (index 1) and the
       sample rate (index 11). alac_reset() in the JNI hardcodes the other
       ten AND the rate, so a sender that differs would decode as noise with
       no other symptom -- hence the refusal below rather than a warning. */
    unsigned short spf = 352;
    unsigned int sr = AUDIO_SAMPLE_RATE;
    val = sdp_attribute(sdp, sdp_len, "fmtp", &val_len);
    if (val && val_len > 0) {
        char fmtp[160] = { 0 };
        int n = val_len < (int) sizeof(fmtp) - 1 ? val_len : (int) sizeof(fmtp) - 1;
        memcpy(fmtp, val, (size_t) n);
        logger_log(raop->logger, LOGGER_INFO, "ANNOUNCE fmtp: %s", fmtp);

        long f[12];
        int nf = 0;
        char *save = NULL;
        for (char *tok = strtok_r(fmtp, " \t", &save); tok && nf < 12;
             tok = strtok_r(NULL, " \t", &save)) {
            f[nf++] = strtol(tok, NULL, 10);
        }
        /* range-checked in the long domain, before any narrowing cast */
        if (nf >= 2 && f[1] >= 64 && f[1] <= 4096) {   /* 4096 == ALAC_MAX_SPF in uxplay_jni.c */
            spf = (unsigned short) f[1];
        }
        if (nf >= 12) {
            /* The decoder is fixed at 44100 (alac_reset sets setinfo_8a_rate)
               and nothing carries a rate down to it, so any other value would
               play at the wrong speed while the RTP clock ran at the announced
               one. Refuse instead. It also keeps a hostile or absurd value out
               of raop_rtp_start_audio, where SECOND_IN_NSECS / sr is integer
               division: anything above 1e9, and anything that wraps to 0 in
               the cast, divides by or yields zero. */
            if (f[11] != AUDIO_SAMPLE_RATE) {
                logger_log(raop->logger, LOGGER_ERR,
                           "ANNOUNCE fmtp sample rate is %ld; only %d is supported",
                           f[11], AUDIO_SAMPLE_RATE);
                http_response_init(response, "RTSP/1.0", 415, "Unsupported Media Type");
                return;
            }
            sr = (unsigned int) f[11];
            if (f[3] != 16 || f[4] != 40 || f[5] != 10 || f[6] != 14 ||
                f[7] != 2 || f[8] != 255) {
                logger_log(raop->logger, LOGGER_WARNING,
                           "ANNOUNCE fmtp is not the canonical ALAC line; alac_reset() hardcodes"
                           " all but frames-per-packet, so audio may decode as noise");
            }
        }
    }

    /* Commit, with the arming flag last. */
    memcpy(conn->classic_aeskey, aeskey, sizeof(conn->classic_aeskey));
    memcpy(conn->classic_aesiv, aesiv, sizeof(conn->classic_aesiv));
    conn->classic_spf = spf;
    conn->classic_sr = sr;
    conn->classic_ct = 2;
    conn->classic_encrypted = encrypted;
    conn->classic_raop = true;

    logger_log(raop->logger, LOGGER_INFO,
               "classic RAOP session announced: ALAC, %u frames/packet, %u Hz",
               conn->classic_spf, conn->classic_sr);
}

/** Answer a classic-RAOP "Apple-Challenge" with "Apple-Response".

    The payload signed is challenge || local IP || MAC, zero-padded to at
    least 32 bytes, RSA-signed with PKCS#1 v1.5 using the AirPort Express
    private key, base64 with the padding stripped. This is shairport-sync's
    apple_challenge() (rtsp.c:3725) reimplemented on our own primitives.

    A sender that gets no Apple-Response hangs up after OPTIONS, which is what
    macOS did when we first advertised as a legacy AirPlay 1 device. */
static void
raop_apple_challenge(raop_conn_t *conn, http_request_t *request, http_response_t *response)
{
    raop_t *raop = conn->raop;
    const char *hdr = http_request_get_header(request, "Apple-Challenge");
    if (!hdr) {
        return;
    }

    unsigned char challenge[16] = { 0 };
    int chall_len = raop_base64_decode(hdr, (int) strlen(hdr), challenge, (int) sizeof(challenge));
    if (chall_len <= 0) {
        logger_log(raop->logger, LOGGER_ERR, "Apple-Challenge did not decode");
        return;
    }

    unsigned char buf[64] = { 0 };
    int n = 0;
    memcpy(buf + n, challenge, (size_t) chall_len);
    n += chall_len;

    /* the address the client reached us on, 4 bytes for IPv4 or 16 for IPv6 */
    if (conn->locallen == 4 || conn->locallen == 16) {
        memcpy(buf + n, conn->local, (size_t) conn->locallen);
        n += conn->locallen;
    } else {
        logger_log(raop->logger, LOGGER_ERR,
                   "Apple-Challenge: unexpected local address length %d", conn->locallen);
        return;
    }

    int hw_len = 0;
    const char *hw_addr = raop->dnssd ? dnssd_get_hw_addr(raop->dnssd, &hw_len) : NULL;
    if (!hw_addr || hw_len != 6) {
        logger_log(raop->logger, LOGGER_ERR, "Apple-Challenge: no usable hardware address");
        return;
    }
    memcpy(buf + n, hw_addr, 6);
    n += 6;

    /* zero-padded to 32; the trailing bytes are already zero */
    if (n < 32) {
        n = 32;
    }

    unsigned char sig[512];
    int sig_len = rsa_auth_sign(buf, n, sig, (int) sizeof(sig));
    if (sig_len == -2) {
        logger_log(raop->logger, LOGGER_ERR,
                   "Apple-Challenge: this build carries no AirPort Express key,"
                   " so a legacy sender will refuse us -- see lib/rsakey.c");
        return;
    }
    if (sig_len <= 0) {
        logger_log(raop->logger, LOGGER_ERR, "Apple-Challenge: signing failed");
        return;
    }

    /* base64, then drop the '=' padding as senders expect */
    char encoded[768] = { 0 };
    pk_to_base64(sig, sig_len, encoded, (int) sizeof(encoded));
    char *pad = strchr(encoded, '=');
    if (pad) {
        *pad = '\0';
    }
    http_response_add_header(response, "Apple-Response", encoded);
    logger_log(raop->logger, LOGGER_INFO, "answered Apple-Challenge (%d-byte signature)", sig_len);
}

/** Read "name=<number>" out of an RTSP Transport header. Returns 0 when the
    parameter is absent or malformed; the caller decides what that means.
    control_port is required, timing_port is not -- without it the NTP thread
    cannot reach the sender and logs every few seconds, but audio still plays,
    because initial_sync comes from the control-port SYNC packet and the
    renderer falls back to local time. That matches what the AirPlay 2 path
    does with a missing timingPort, deliberately. */
static unsigned short
transport_port(const char *transport, const char *name)
{
    const char *p = transport;
    size_t name_len = strlen(name);

    while ((p = strstr(p, name)) != NULL) {
        /* must be a whole parameter, not the tail of another: control_port
           ends in "_port" and would otherwise match a search for "port" */
        if (p != transport && p[-1] != ';' && p[-1] != ' ') {
            p += name_len;
            continue;
        }
        if (p[name_len] != '=') {
            p += name_len;
            continue;
        }
        long v = strtol(p + name_len + 1, NULL, 10);
        return (v > 0 && v <= 65535) ? (unsigned short) v : 0;
    }
    return 0;
}

/** The classic RAOP SETUP: everything it needs arrived in ANNOUNCE except the
    sender's two port numbers, which are in the Transport header. */
static void
raop_handler_setup_classic(raop_conn_t *conn, const char *transport,
                           const char *dacp_id, const char *active_remote_header,
                           http_response_t *response)
{
    raop_t *raop = conn->raop;

    if (!conn->classic_raop) {
        logger_log(raop->logger, LOGGER_ERR,
                   "classic SETUP without a preceding ANNOUNCE on this connection");
        http_response_init(response, "RTSP/1.0", 455, "Method Not Valid in This State");
        return;
    }

    unsigned short control_rport = transport_port(transport, "control_port");
    unsigned short timing_rport = transport_port(transport, "timing_port");
    if (!control_rport) {
        logger_log(raop->logger, LOGGER_ERR, "classic SETUP Transport has no usable control_port: %s",
                   transport);
        http_response_init(response, "RTSP/1.0", 461, "Unsupported Transport");
        return;
    }

    /* A second SETUP on the same connection would otherwise leak the first
       session's threads and sockets. The AirPlay 2 path above NULLs these
       without destroying them; do not copy that here.

       Order matters, and it is the order conn_destroy uses: rtp, then mirror,
       then ntp. Both raop_rtp and raop_rtp_mirror cache the raop_ntp pointer
       (raop_rtp.c:152, raop_rtp_mirror.c:149) and neither clears it on stop,
       so destroying ntp first would leave the mirror thread writing into
       freed memory -- raop_ntp_set_video_arrival_offset is a bare unguarded
       store of a value taken straight off the wire. The mirror is created
       unconditionally by the AirPlay 2 ekey/eiv block, for audio-only
       sessions too, so it can be live here even though classic RAOP has no
       video of its own. */
    if (conn->raop_rtp) {
        raop_rtp_stop(conn->raop_rtp);
        raop_rtp_destroy(conn->raop_rtp);
        conn->raop_rtp = NULL;
    }
    if (conn->raop_rtp_mirror) {
        raop_rtp_mirror_stop(conn->raop_rtp_mirror);
        raop_rtp_mirror_destroy(conn->raop_rtp_mirror);
        conn->raop_rtp_mirror = NULL;
    }
    if (conn->raop_ntp) {
        /* raop_ntp_destroy stops it itself (raop_ntp.c:201) */
        raop_ntp_destroy(conn->raop_ntp);
        conn->raop_ntp = NULL;
    }

    char remote[40] = { 0 };
    int len = utils_ipaddress_to_string(conn->remotelen, conn->remote, conn->zone_id,
                                        remote, (int) sizeof(remote));
    if (!len || len > (int) sizeof(remote)) {
        logger_log(raop->logger, LOGGER_ERR,
                   "classic SETUP: could not render the client address; cannot reply to it");
        http_response_init(response, "RTSP/1.0", 500, "Internal Server Error");
        return;
    }

    /* Classic RAOP is the "old protocol without offset" that raop_ntp names
       TP_UNSPECIFIED -- it predates AirPlay 2's timingProtocol negotiation. */
    timing_protocol_t time_protocol = TP_UNSPECIFIED;
    unsigned short timing_lport = raop->timing_lport;

    conn->raop_ntp = raop_ntp_init(raop->logger, &raop->callbacks, remote, conn->remotelen,
                                   timing_rport, &time_protocol);
    if (!conn->raop_ntp) {
        logger_log(raop->logger, LOGGER_ERR, "classic SETUP: raop_ntp_init failed");
        http_response_init(response, "RTSP/1.0", 500, "Internal Server Error");
        return;
    }
    raop_ntp_start(conn->raop_ntp, &timing_lport);
    conn->raop_rtp = raop_rtp_init(raop->logger, &raop->callbacks, conn->raop_ntp,
                                   remote, conn->remotelen,
                                   conn->classic_encrypted ? conn->classic_aeskey : NULL,
                                   conn->classic_encrypted ? conn->classic_aesiv : NULL);
    if (!conn->raop_rtp) {
        logger_log(raop->logger, LOGGER_ERR, "classic SETUP: raop_rtp_init failed");
        http_response_init(response, "RTSP/1.0", 500, "Internal Server Error");
        return;
    }

    /* Tell the renderers what is coming. This is what resets the ALAC decoder
       to the announced frames-per-packet; without it a non-default spf decodes
       as noise. usingScreen/isMedia are false: classic RAOP has no video. */
    unsigned char ct = conn->classic_ct;
    unsigned short spf = conn->classic_spf;
    bool using_screen = false, is_media = false;
    uint64_t audio_format = 0;
    if (raop->callbacks.audio_get_format) {
        raop->callbacks.audio_get_format(raop->callbacks.cls, &ct, &spf, &using_screen,
                                         &is_media, &audio_format);
    }

    /* Seed from config, as the AirPlay 2 audio case does: uxplay's -p exists
       to pin exactly these ports for a firewall, and 6000/6001/7011 are the
       classic-RAOP numbers. On porg all three are 0, meaning "any". */
    unsigned short control_lport = raop->control_lport, data_lport = raop->data_lport;
    unsigned int sr = conn->classic_sr;
    raop_rtp_start_audio(conn->raop_rtp, &control_rport, &control_lport, &data_lport, &ct, &sr);

    /* raop_rtp_start_audio returns void and simply does not write back the
       out-params if the sockets fail, which would leave us answering 200 with
       server_port=0 and the sender streaming into nowhere with nothing to
       diagnose. Treat a zero port as the failure it is. */
    if (!control_lport || !data_lport) {
        logger_log(raop->logger, LOGGER_ERR,
                   "classic SETUP: audio sockets failed to bind (control=%u data=%u)",
                   control_lport, data_lport);
        raop_rtp_stop(conn->raop_rtp);
        raop_rtp_destroy(conn->raop_rtp);
        conn->raop_rtp = NULL;
        http_response_init(response, "RTSP/1.0", 500, "Internal Server Error");
        return;
    }

    char reply[256];
    snprintf(reply, sizeof(reply),
             "RTP/AVP/UDP;unicast;mode=record;server_port=%u;control_port=%u;timing_port=%u",
             data_lport, control_lport, timing_lport);
    http_response_add_header(response, "Transport", reply);
    http_response_add_header(response, "Session", "1");
    /* No Audio-Jack-Status here: conn_request already added
       "connected; type=digital" to every CSeq-bearing non-RECORD response
       (raop.c:374-376), and add_header only appends -- a second one would
       leave two contradictory values on the wire. digital is also the
       truthful value for an HDMI sink. */

    /* Re-register DACP. raop_handler_setup does this before the Transport
       branch, against a conn->raop_rtp that is NULL on a first classic SETUP
       and is destroyed and recreated above on a second one, so without this
       a classic session never gets remote control. The AirPlay 2 path is
       unaffected: its raop_rtp already exists by then. */
    if (dacp_id && active_remote_header) {
        raop_rtp_remote_control_id(conn->raop_rtp, dacp_id, active_remote_header);
    }

    logger_log(raop->logger, LOGGER_INFO,
               "classic RAOP audio: server_port=%u control_port=%u timing_port=%u"
               " (client control_port=%u timing_port=%u)",
               data_lport, control_lport, timing_lport, control_rport, timing_rport);
}

static void
raop_handler_setup(raop_conn_t *conn,
                   http_request_t *request, http_response_t *response,
                   char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    const char *dacp_id = NULL;
    const char *active_remote_header = NULL;
    bool logger_debug = (logger_get_level(raop->logger) >= LOGGER_DEBUG);

    if (!pin_gate(conn, response, "SETUP")) {
        return;
    }
    
    const char *data = NULL;
    int data_len = 0;
    data = http_request_get_data(request, &data_len);

    dacp_id = http_request_get_header(request, "DACP-ID");
    active_remote_header = http_request_get_header(request, "Active-Remote");

    if (dacp_id && active_remote_header) {
        logger_log(raop->logger, LOGGER_DEBUG, "DACP-ID: %s", dacp_id);
        logger_log(raop->logger, LOGGER_DEBUG, "Active-Remote: %s", active_remote_header);
        if (conn->raop_rtp) {
            raop_rtp_remote_control_id(conn->raop_rtp, dacp_id, active_remote_header);
        }
    }

    /* Classic RAOP SETUP: no body at all, parameters in a Transport: header.
       This must branch BEFORE plist_from_bin below -- falling through does not
       crash, it answers 200 with an empty dict and no Transport header, and a
       silent success is worse for the sender than an honest refusal. */
    const char *transport = http_request_get_header(request, "Transport");
    if (transport) {
        raop_handler_setup_classic(conn, transport, dacp_id, active_remote_header, response);
        return;
    }

    // Parsing bplist
    plist_t req_root_node = NULL;
    plist_from_bin(data, data_len, &req_root_node);
    plist_t req_ekey_node = plist_dict_get_item(req_root_node, "ekey");
    plist_t req_eiv_node = plist_dict_get_item(req_root_node, "eiv");
	
    // For the response
    plist_t res_root_node = plist_new_dict();

    if (PLIST_IS_DATA(req_eiv_node) && PLIST_IS_DATA(req_ekey_node)) {
        // The first SETUP call that initializes keys and timing

        /* 16 and 72 bytes are copied out of these below, whatever size the
           client sent: refuse anything else rather than read past them. */
        uint64_t eiv_size = 0, ekey_size = 0;
        plist_get_data_ptr(req_eiv_node, &eiv_size);
        plist_get_data_ptr(req_ekey_node, &ekey_size);
        if (eiv_size != 16 || ekey_size != 72) {
            logger_log(raop->logger, LOGGER_ERR, "SETUP with a %llu-byte eiv and a %llu-byte ekey;"
                       " expected 16 and 72", (unsigned long long) eiv_size, (unsigned long long) ekey_size);
            http_response_init(response, "RTSP/1.0", 400, "Bad Request");
            plist_free(res_root_node);
            plist_free(req_root_node);
            return;
        }

        unsigned char aesiv[16] = { 0 };
        unsigned char aeskey[16] = { 0 };
        unsigned char eaeskey[72] = { 0 };

        logger_log(raop->logger, LOGGER_DEBUG, "SETUP 1");

        // First setup

        char *deviceID = NULL;
        plist_t req_deviceid_node = plist_dict_get_item(req_root_node, "deviceID");
        plist_get_string_val(req_deviceid_node, &deviceID);  


        /* RFC2617 Digest authentication (md5 hash) of uxplay client-access password, if set */
        if (!conn->authenticated && raop->callbacks.passwd) {
            size_t pin_len = 4;
            const char *authorization = NULL;
            authorization = http_request_get_header(request, "Authorization");
            if (!authorization) {
                // if random_pw is set, but client has changed, unset it 
                if (raop->random_pw && strncmp(raop->random_pw + pin_len + 1,  deviceID, 17)) {
                    free(raop->random_pw);
                    raop->random_pw = NULL;
                }
            }
            int len = 0;
            const char *password = raop->callbacks.passwd(raop->callbacks.cls, &len);
            // len = -1 means use a random password for this connection; len = 0 means no password
            if (len == -1 && raop->random_pw && raop->auth_fail_count >= MAX_PW_ATTEMPTS) {
                // change random_pw after MAX_PW_ATTEMPTS  failed authentication attempts
                logger_log(raop->logger, LOGGER_INFO, "Too many authentication failures: generate new random password");
                free(raop->random_pw);
                raop->random_pw = NULL;
            }
            if (len == -1 && !raop->random_pw) {
                // get and store 4 random digits
                int pin_4  = random_pin();
                if (pin_4 < 0) {
                    logger_log(raop->logger, LOGGER_ERR, "Failed to generate random pin");
                    pin_4 = 1234;
                }
                if ((raop->random_pw =  (char *) calloc(pin_len + 1 + 18, sizeof(char)))) {
                    char *pin = raop->random_pw;
                    snprintf(pin, pin_len + 1, "%04u", pin_4 % 10000);
                    pin[pin_len] = '\0';
                    snprintf(pin + pin_len + 1, 18, "%s", deviceID);
                } else {
                    logger_log(raop->logger, LOGGER_ERR, "Failed to allocate raop->random_pw");
                }
                raop->auth_fail_count = 0;
            }
            if (len == -1 && !authorization && raop->random_pw) {
                if (raop->callbacks.display_pin) {
                    raop->callbacks.display_pin(raop->callbacks.cls, raop->random_pw);
                }
                logger_log(raop->logger, LOGGER_INFO, "*** CLIENT MUST NOW ENTER PIN = \"%s\" AS AIRPLAY PASSWORD", raop->random_pw);
                raop->auth_fail_count++;
            }
	    if (len && !conn->authenticated) {
 	        if (len == -1) {
                    password = (const char *) raop->random_pw;
                }
                char nonce_string[33] = { '\0' };
                //bool stale = false;  //not implemented
                if (len && authorization) {
                    const char *ptr = strstr(authorization, "nonce=\"") +  strlen("nonce=\"");
                    strncpy(nonce_string, ptr, 32);
                    const char *method = http_request_get_method(request);
                    conn->authenticated = pairing_digest_verify(method, authorization, password);
		    if (!conn->authenticated) {
                        // if random_pw is used, the auth_fail_count will be the number of times it is displayed after creation
                        if (len != -1) {
                            raop->auth_fail_count++;
                        }
                        logger_log(raop->logger, LOGGER_INFO, "*** authentication failure: count = %u", raop->auth_fail_count);
                    }
                    if (conn->authenticated) {
                        //printf("initial authenticatication OK\n");
                        conn->authenticated = conn->authenticated && !strcmp(nonce_string, raop->nonce);
                        if (!conn->authenticated) {
                            logger_log(raop->logger, LOGGER_INFO, "authentication rejected (nonce mismatch) %s %s",
                                       nonce_string, raop->nonce);
                        }			
                    }
                    if (conn->authenticated && raop->random_pw) {
                        free (raop->random_pw);
                        raop->random_pw = NULL;
                    }
                    if (raop->nonce) {
                        free(raop->nonce);
                        raop->nonce = NULL;
                    }
                    logger_log(raop->logger, LOGGER_INFO, "Client authentication %s", (conn->authenticated ? "success" : "failure"));
                }
                if (!conn->authenticated) {
                    /* create a nonce */
                    const char *url = http_request_get_url(request);
                    unsigned char nonce[16] = { '\0' };
                    int len = 16;
                    uint64_t now = raop_ntp_get_local_time();
                    assert (!pairing_session_make_nonce(conn->session, &now, url, nonce, len));
                    if (raop->nonce) {
                        free(raop->nonce);
                    }
                    raop->nonce = utils_hex_to_string(nonce, len);
                    char response_text[80] = "Digest realm=\"raop\", nonce=\"";
                    strncat(response_text, raop->nonce, 80 - strlen(response_text) - 1);
                    strncat(response_text, "\"", 80 - strlen(response_text) - 1);
                    http_response_init(response, "RTSP/1.0", 401, "Unauthorized");
                    http_response_add_header(response, "WWW-Authenticate", response_text);
                    return;
                }
            }
        }
	
        char* eiv = NULL;
        uint64_t eiv_len = 0;
        char *model = NULL;
        char *name = NULL;
        bool admit_client = true;
        plist_t req_model_node = plist_dict_get_item(req_root_node, "model");
        plist_get_string_val(req_model_node, &model);  
        plist_t req_name_node = plist_dict_get_item(req_root_node, "name");
        plist_get_string_val(req_name_node, &name);  
        if (raop->callbacks.report_client_request) {
            raop->callbacks.report_client_request(raop->callbacks.cls, deviceID, model, name, &admit_client);
        }
        if (admit_client && deviceID && name && raop->callbacks.register_client) {
            char *client_device_id = NULL;
            char *client_pk = NULL;   /* encoded as null-terminated  base64 string, must be freed*/
            get_pairing_session_client_data(conn->session, &client_device_id, &client_pk);
            if (client_pk && !strcmp(deviceID, client_device_id)) { 
                raop->callbacks.register_client(raop->callbacks.cls, client_device_id, client_pk, name); 
                free (client_pk);
            }
        }
        plist_mem_free(deviceID);
        deviceID = NULL;
        plist_mem_free(model);
        model = NULL;
        plist_mem_free(name);
        name = NULL;
        if (admit_client == false) {
            /* client is not authorized to connect */
            plist_free(res_root_node);
            plist_free(req_root_node);
            return;
        }

        plist_get_data_val(req_eiv_node, &eiv, &eiv_len);
        memcpy(aesiv, eiv, 16);
        free(eiv);	
        logger_log(raop->logger, LOGGER_DEBUG, "eiv_len = %llu", eiv_len);
        if (logger_debug) {
            char* str = utils_data_to_string(aesiv, 16, 16);
            logger_log(raop->logger, LOGGER_DEBUG, "16 byte aesiv (needed for AES-CBC audio decryption iv):\n%s", str);
            free(str);
        }

        char* ekey = NULL;
        uint64_t ekey_len = 0;
        plist_get_data_val(req_ekey_node, &ekey, &ekey_len);
        memcpy(eaeskey,ekey,72);
        free(ekey);
        logger_log(raop->logger, LOGGER_DEBUG, "ekey_len = %llu", ekey_len);
        // eaeskey is 72 bytes, aeskey is 16 bytes
        if (logger_debug) {
            char *str = utils_data_to_string((unsigned char *) eaeskey, ekey_len, 16);
            logger_log(raop->logger, LOGGER_DEBUG, "ekey:\n%s", str);
            free (str);
        }
        int ret = fairplay_decrypt(conn->fairplay, (unsigned char*) eaeskey, aeskey);
        logger_log(raop->logger, LOGGER_DEBUG, "fairplay_decrypt ret = %d", ret);
        if (logger_debug) {
            char *str = utils_data_to_string(aeskey, 16, 16);
            logger_log(raop->logger, LOGGER_DEBUG, "16 byte aeskey (fairplay-decrypted from ekey):\n%s", str);
            free(str);
        }

        bool old_protocol = false;
        const char *user_agent = http_request_get_header(request, "User-Agent");
        if (user_agent) {
            logger_log(raop->logger, LOGGER_INFO, "Client identified as User-Agent: %s", user_agent);	
#ifdef OLD_PROTOCOL_CLIENT_USER_AGENT_LIST    /* set in global.h */
            if (strstr(OLD_PROTOCOL_CLIENT_USER_AGENT_LIST, user_agent)) old_protocol = true;
            if (strstr(user_agent, "AirMyPC")) old_protocol = true;   //AirMyPC/7200 still uses old protocol: unlikely to change (?)
#endif
        }	
        if  (old_protocol) {    /* some windows AirPlay-client emulators use old AirPlay 1 protocol with unhashed AES key */
            logger_log(raop->logger, LOGGER_INFO, "Client identifed as using old protocol (unhashed) AES audio key)");
        } else {
            unsigned char ecdh_secret[X25519_KEY_SIZE];
            if (pairing_get_ecdh_secret_key(conn->session, ecdh_secret)) {
                /* In this case  (legacy) pairing with client was successfully set up and created the shared ecdh_secret:
                 * aeskey must now be hashed with it
                 *
                 * If byte 27 of features ("supports legacy pairing") is turned off, the client does not request pairsetup
                 * and does NOT set up pairing (this eliminates a 5 second delay in connecting with no apparent bad effects).
                 * In this case, ecdh_secret does not exist, so aeskey should NOT be hashed with it.

                 * UxPlay may be able to function with byte 27 turned off because it currently does not support connections 
                 * with more than one client at a time. AppleTV supports up to 12 clients, uses pairing to give each a distinct
                 * SessionID and ecdh_secret.
            
                 * The "old protocol" Windows AirPlay client AirMyPC seems not to respect the byte 27 setting, and always sets
                 * up the  ecdh_secret, but decryption fails if aeskey is hashed.*/

                if (logger_debug) {
                    char *str = utils_data_to_string(ecdh_secret, X25519_KEY_SIZE, 16);
                    logger_log(raop->logger, LOGGER_DEBUG, "32 byte shared ecdh_secret:\n%s", str);
                    free(str);
                }
                memcpy(eaeskey, aeskey, 16);
                sha_ctx_t *ctx = sha_init();
                sha_update(ctx, eaeskey, 16);
                sha_update(ctx, ecdh_secret, 32);
                sha_final(ctx, eaeskey, NULL);
                sha_destroy(ctx);
                memcpy(aeskey, eaeskey, 16);
                if (logger_debug) {
                    char *str = utils_data_to_string(aeskey, 16, 16);
                    logger_log(raop->logger, LOGGER_DEBUG, "16 byte aeskey after sha-256 hash with ecdh_secret:\n%s", str);
                    free(str);
                }
            }
        }

        // Time port
        plist_t req_is_remote_control_only_node = plist_dict_get_item(req_root_node, "isRemoteControlOnly");
        if (req_is_remote_control_only_node) {
	    uint8_t bool_val = 0;
	    plist_get_bool_val(req_is_remote_control_only_node, &bool_val);  
            if (bool_val) {
                logger_log(raop->logger, LOGGER_ERR, "Client specified AirPlay2 \"Remote Control\" protocol\n"
			   " Only AirPlay v1 protocol (using NTP and timing port) is supported");
            }
        }
        char *timing_protocol = NULL;
        timing_protocol_t time_protocol = TP_NONE;
        plist_t req_timing_protocol_node = plist_dict_get_item(req_root_node, "timingProtocol");
        plist_get_string_val(req_timing_protocol_node, &timing_protocol);
        if (timing_protocol) {
             int string_len = strlen(timing_protocol);
             if (strncmp(timing_protocol, "NTP", string_len) == 0) {
                 time_protocol = NTP;
             } else if (strncmp(timing_protocol, "None", string_len) == 0) {
                 time_protocol = TP_NONE;
             } else {
                 time_protocol = TP_OTHER;
             }
             if (time_protocol != NTP) {
                 logger_log(raop->logger, LOGGER_ERR, "Client specified timingProtocol=%s,"
                            " but timingProtocol= NTP is required here", timing_protocol);
             }
             plist_mem_free (timing_protocol);
             timing_protocol = NULL;
        } else {
            logger_log(raop->logger, LOGGER_DEBUG, "Client did not specify timingProtocol,"
                       " old protocol without offset will be used");
            time_protocol = TP_UNSPECIFIED;
        }
        uint64_t timing_rport = 0;
        plist_t req_timing_port_node = plist_dict_get_item(req_root_node, "timingPort");
        if (req_timing_port_node) {
             plist_get_uint_val(req_timing_port_node, &timing_rport);
        }
        if (timing_rport) {
            logger_log(raop->logger, LOGGER_DEBUG, "timing_rport = %llu", timing_rport);
        } else {
            logger_log(raop->logger, LOGGER_ERR, "Client did not supply timing_rport,"
                       " may be using unsupported AirPlay2 \"Remote Control\" protocol");
        }
        unsigned short timing_lport = raop->timing_lport;

        conn->raop_ntp = NULL;
        conn->raop_rtp = NULL;
        conn->raop_rtp_mirror = NULL;
        char remote[40] = { 0 };
        int len = utils_ipaddress_to_string(conn->remotelen, conn->remote, conn->zone_id, remote, (int) sizeof(remote));
        if (!len || len > (int) sizeof(remote)) {
            char *str = utils_data_to_string(conn->remote, conn->remotelen, 16);
            logger_log(raop->logger, LOGGER_ERR, "failed to extract valid client ip address:\n"
                       "*** UxPlay will be unable to send communications to client.\n"
                       "*** address length %d, zone_id %u address data:\n%sparser returned \"%s\"\n",
                       conn->remotelen, conn->zone_id, str, remote);
            free(str);
        }
        conn->raop_ntp = raop_ntp_init(raop->logger, &raop->callbacks, remote,
                                       conn->remotelen, (unsigned short) timing_rport, &time_protocol);
        raop_ntp_start(conn->raop_ntp, &timing_lport);
        conn->raop_rtp = raop_rtp_init(raop->logger, &raop->callbacks, conn->raop_ntp,
                                       remote, conn->remotelen, aeskey, aesiv);
        conn->raop_rtp_mirror = raop_rtp_mirror_init(raop->logger, &raop->callbacks,
                                                     conn->raop_ntp, remote, conn->remotelen, aeskey);

        /* the event port is not used in mirror mode or audio mode */
        unsigned short event_port = 0;
        plist_t res_event_port_node = plist_new_uint(event_port);
        plist_t res_timing_port_node = plist_new_uint(timing_lport);
        plist_dict_set_item(res_root_node, "timingPort", res_timing_port_node);
        plist_dict_set_item(res_root_node, "eventPort", res_event_port_node);

        logger_log(raop->logger, LOGGER_DEBUG, "eport = %d, tport = %d", event_port, timing_lport);
    }

    // Process stream setup requests
    plist_t req_streams_node = plist_dict_get_item(req_root_node, "streams");
    if (PLIST_IS_ARRAY(req_streams_node)) {
        plist_t res_streams_node = plist_new_array();

        int count = plist_array_get_size(req_streams_node);
        for (int i = 0; i < count; i++) {
            plist_t req_stream_node = plist_array_get_item(req_streams_node, i);
            plist_t req_stream_type_node = plist_dict_get_item(req_stream_node, "type");
            uint64_t type;
            plist_get_uint_val(req_stream_type_node, &type);
            logger_log(raop->logger, LOGGER_DEBUG, "type = %llu", type);

            switch (type) {
            case 110: {
                // Mirroring
                if (raop->use_pin && !pin_proved(conn)) {
                    /* Only reachable with open_audio on: the gate above let
                       this connection through without a pin so that audio
                       could work. Mirroring is not part of that bargain, and
                       this is the first point where the request says which it
                       is -- so the exemption cannot be something the sender
                       chooses by declaring itself audio-only. */
                    logger_log(raop->logger, LOGGER_ERR,
                               "SETUP: mirroring refused, the client has not paired with the pin");
                    http_response_init(response, "RTSP/1.0", 470, "Client Authentication Failure");
                    plist_free(req_root_node);
                    plist_free(res_streams_node);
                    return;
                }
                raop_destroy_airplay_video(raop, -1);  //cleanup any hls data still present when mirror video starts
                unsigned short dport = raop->mirror_data_lport;
                plist_t stream_id_node = plist_dict_get_item(req_stream_node, "streamConnectionID");
                uint64_t stream_connection_id = 0;
                plist_get_uint_val(stream_id_node, &stream_connection_id);
                logger_log(raop->logger, LOGGER_DEBUG, "streamConnectionID (needed for AES-CTR video decryption"
                           " key and iv): %llu", stream_connection_id);

                if (conn->raop_rtp_mirror) {
                    raop_rtp_mirror_init_aes(conn->raop_rtp_mirror, &stream_connection_id);
                    raop_rtp_mirror_start(conn->raop_rtp_mirror, &dport, raop->clientFPSdata);
                    logger_log(raop->logger, LOGGER_DEBUG, "Mirroring initialized successfully");
                } else {
                    logger_log(raop->logger, LOGGER_ERR, "Mirroring not initialized at SETUP, playing will fail!");
                    http_response_set_disconnect(response, 1);
                }

                plist_t res_stream_node = plist_new_dict();
                plist_t res_stream_data_port_node = plist_new_uint(dport);
                plist_t res_stream_type_node = plist_new_uint(110);
                plist_dict_set_item(res_stream_node, "dataPort", res_stream_data_port_node);
                plist_dict_set_item(res_stream_node, "type", res_stream_type_node);
                plist_array_append_item(res_streams_node, res_stream_node);

                break;
                }
            case 96: {
                // Audio
                unsigned short cport = raop->control_lport, dport = raop->data_lport; 
                unsigned short remote_cport = 0;
                unsigned char ct = 0;
                unsigned int sr = AUDIO_SAMPLE_RATE; /* all AirPlay audio formats supported so far have sample rate 44.1kHz */

                uint64_t uint_val = 0;
                plist_t req_stream_control_port_node = plist_dict_get_item(req_stream_node, "controlPort");
                plist_get_uint_val(req_stream_control_port_node, &uint_val);
                remote_cport = (unsigned short) uint_val;   /* must != 0 to activate audio resend requests */

                plist_t req_stream_ct_node = plist_dict_get_item(req_stream_node, "ct");
                plist_get_uint_val(req_stream_ct_node, &uint_val);
                ct = (unsigned char) uint_val;

                if (raop->callbacks.audio_get_format) {
                    /* get additional audio format parameters  */
                    uint64_t audioFormat = 0;
                    unsigned short spf = 0;
                    bool isMedia = false;
                    bool usingScreen = false;
                    uint8_t bool_val = 0;

                    plist_t req_stream_spf_node = plist_dict_get_item(req_stream_node, "spf");
                    plist_get_uint_val(req_stream_spf_node, &uint_val);
                    spf = (unsigned short) uint_val;

                    plist_t req_stream_audio_format_node = plist_dict_get_item(req_stream_node, "audioFormat");
                    plist_get_uint_val(req_stream_audio_format_node, &audioFormat);

                    plist_t req_stream_is_media_node = plist_dict_get_item(req_stream_node, "isMedia");
                    if (req_stream_is_media_node) {
                        plist_get_bool_val(req_stream_is_media_node, &bool_val);
                        isMedia = (bool) bool_val;
                    } else {
                        isMedia = false;
                    }

                    plist_t req_stream_using_screen_node = plist_dict_get_item(req_stream_node, "usingScreen");
                    if (req_stream_using_screen_node) {
                        plist_get_bool_val(req_stream_using_screen_node, &bool_val);
                        usingScreen = (bool) bool_val;
                    } else {
                        usingScreen = false;
                    }

                    raop->callbacks.audio_get_format(raop->callbacks.cls, &ct, &spf, &usingScreen, &isMedia, &audioFormat);
                }

                if (conn->raop_rtp) {
                    raop_rtp_start_audio(conn->raop_rtp, &remote_cport, &cport, &dport, &ct, &sr);
                    logger_log(raop->logger, LOGGER_DEBUG, "RAOP initialized success");
                } else {
                    logger_log(raop->logger, LOGGER_ERR, "RAOP not initialized at SETUP, playing will fail!");
                    http_response_set_disconnect(response, 1);
                }

                plist_t res_stream_node = plist_new_dict();
                plist_t res_stream_data_port_node = plist_new_uint(dport);
                plist_t res_stream_control_port_node = plist_new_uint(cport);
                plist_t res_stream_type_node = plist_new_uint(96);
                plist_dict_set_item(res_stream_node, "dataPort", res_stream_data_port_node);
                plist_dict_set_item(res_stream_node, "controlPort", res_stream_control_port_node);
                plist_dict_set_item(res_stream_node, "type", res_stream_type_node);
                plist_array_append_item(res_streams_node, res_stream_node);

                break;
                }

            default:
                logger_log(raop->logger, LOGGER_ERR, "SETUP tries to setup stream of unknown type %llu", type);
                http_response_set_disconnect(response, 1);
                break;
            }
        }

        plist_dict_set_item(res_root_node, "streams", res_streams_node);
    }

    plist_to_bin(res_root_node, response_data, (uint32_t*) response_datalen);
    plist_free(res_root_node);
    plist_free(req_root_node);
    http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
}

static void
raop_handler_get_parameter(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;  
    const char *content_type = NULL;
    const char *data = NULL;
    int datalen = 0;

    content_type = http_request_get_header(request, "Content-Type");
    if (!content_type) {
        http_response_init(response, "RTSP/1.0", 451, "Parameter not understood");
        return;
    }

    data = http_request_get_data(request, &datalen);
    if (!strcmp(content_type, "text/parameters")) {
        const char *current = data;

        while (current && (datalen - (current - data) > 0)) {
            const char *next;

            /* This is a bit ugly, but seems to be how airport works too */
            if ((datalen - (current - data) >= 8) && !strncmp(current, "volume\r\n", 8)) {
                char volume[25] = "volume: 0.0\r\n";
                if (raop->callbacks.audio_set_client_volume) {
                    snprintf(volume, 25, "volume: %9.6f\r\n", raop->callbacks.audio_set_client_volume(raop->callbacks.cls));
                }
                http_response_add_header(response, "Content-Type", "text/parameters");
                *response_data = strdup(volume);
                if (*response_data) {
                    *response_datalen = strlen(*response_data);
                }
                return;
            }

            for (next = current ; (datalen - (next - data) > 0) ; ++next) {
                if (*next == '\r') {
                    break;
                }
            }

            if ((datalen - (next - data) >= 2) && !strncmp(next, "\r\n", 2)) {
                if ((next - current) > 0) {
                    logger_log(raop->logger, LOGGER_WARNING,
                               "Found an unknown parameter: %.*s", (next - current), current);
                }
                current = next + 2;
            } else {
                current = NULL;
            }
        }
    }
}

static void
raop_handler_set_parameter(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    const char *content_type = NULL;
    const char *data = NULL;
    int datalen = 0;

    content_type = http_request_get_header(request, "Content-Type");
    if (!content_type) {
        logger_log(raop->logger, LOGGER_WARNING, "SET_PARAMETER with no Content-Type");
        http_response_init(response, "RTSP/1.0", 451, "Parameter not understood");
        return;
    }
    data = http_request_get_data(request, &datalen);
    /* At INFO deliberately: which parameters a sender actually sends, and
       when, is the first question in any now-playing or metadata problem, and
       at DEBUG it is invisible on an image that ships log.tag=I. One line per
       request, no payload.

       text/parameters is excluded because it carries progress about once a
       second for as long as audio plays, and a line per second forever is not
       instrumentation, it is noise. The length is bounded because
       content_type is an unbounded header from an unauthenticated LAN peer --
       SET_PARAMETER has no pairing gate. */
    if (strcmp(content_type, "text/parameters")) {
        logger_log(raop->logger, LOGGER_INFO, "SET_PARAMETER %.64s, %d bytes", content_type, datalen);
    }
    if (!strcmp(content_type, "text/parameters")) {
        char *datastr = NULL;
        datastr = calloc(1, datalen + 1);
        if (data && datastr && conn->raop_rtp) {
            memcpy(datastr, data, datalen);
            if ((datalen >= 8) && !strncmp(datastr, "volume: ", 8)) {
                float vol = 0.0f;
                sscanf(datastr+8, "%f", &vol);
                if (raop_rtp_is_running(conn->raop_rtp)) {
                    raop_rtp_set_volume(conn->raop_rtp, vol);
                } else if (raop->callbacks.audio_set_volume) {
                    /* set volume in playbin (hls) */
                    raop->callbacks.audio_set_volume(raop->callbacks.cls, vol);
                }
            } else if ((datalen >= 10) && !strncmp(datastr, "progress: ", 10)) {
                uint32_t start = 0, curr = 0, end = 0;
                sscanf(datastr+10, "%"PRIu32"/%"PRIu32"/%"PRIu32, &start, &curr, &end);
                raop_rtp_set_progress(conn->raop_rtp, start, curr, end);
            }
        } else if (!conn->raop_rtp) {
            logger_log(raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER");
        }
        free(datastr);
    } else if (!strcmp(content_type, "image/jpeg") || !strcmp(content_type, "image/png")) {
        logger_log(raop->logger, LOGGER_DEBUG, "Got image data of %d bytes", datalen);
        if (conn->raop_rtp) {
            raop_rtp_set_coverart(conn->raop_rtp, data, datalen);
        } else {
            logger_log(raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER coverart");
        }
    } else if (!strcmp(content_type, "application/x-dmap-tagged")) {
        logger_log(raop->logger, LOGGER_DEBUG, "Got metadata of %d bytes", datalen);
        if (conn->raop_rtp) {
            raop_rtp_set_metadata(conn->raop_rtp, data, datalen);
        } else {
            logger_log(raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER metadata");
        }
    } else {
        /* The chain had no final else, so a type we do not handle vanished
           without trace at any log level -- including image/none, which some
           senders use to say "this track has no artwork". */
        logger_log(raop->logger, LOGGER_INFO, "SET_PARAMETER: unhandled Content-Type %.64s", content_type);
    }
}

static void
raop_handler_audiomode(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    const char *data = NULL;
    char *audiomode = NULL;
    int data_len = 0;
    data = http_request_get_data(request, &data_len);
    plist_t req_root_node = NULL;
    plist_from_bin(data, data_len, &req_root_node);
    plist_t req_audiomode_node = plist_dict_get_item(req_root_node, "audioMode");
    plist_get_string_val(req_audiomode_node, &audiomode);
    if (audiomode) {
        /* not sure what should be done with this request: usually audioMode requested is "default" */
        int log_level = (strstr(audiomode, "default") ? LOGGER_DEBUG : LOGGER_INFO);
        logger_log(raop->logger, log_level, "Unhandled RTSP request \"audioMode: %s\"", audiomode);
        plist_mem_free(audiomode);
    }
    plist_free(req_root_node);
}

static void
raop_handler_feedback(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    logger_log(raop->logger, LOGGER_DEBUG, "raop_handler_feedback");
    /* register receipt of client's "heartbeat" signal  */
    raop->callbacks.conn_feedback(raop->callbacks.cls);
}

static void
raop_handler_record(raop_conn_t *conn,
                    http_request_t *request, http_response_t *response,
                    char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    char audio_latency[12] = { '\0' };
    unsigned int ad = (unsigned int) (((uint64_t) raop->audio_delay_micros) * AUDIO_SAMPLE_RATE / SECOND_IN_USECS);
    snprintf(audio_latency, sizeof(audio_latency), "%u", ad);
    logger_log(raop->logger, LOGGER_DEBUG, "raop_handler_record");
    http_response_add_header(response, "Audio-Latency", audio_latency);
    http_response_add_header(response, "Audio-Jack-Status", "connected; type=analog");
}

static void
raop_handler_flush(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    raop_t *raop = conn->raop;
    const char *rtpinfo = NULL;
    int next_seq = -1;

    rtpinfo = http_request_get_header(request, "RTP-Info");
    if (rtpinfo) {
        logger_log(raop->logger, LOGGER_DEBUG, "Flush with RTP-Info: %s", rtpinfo);
        if (!strncmp(rtpinfo, "seq=", 4)) {
            next_seq = strtol(rtpinfo + 4, NULL, 10);
        }
    }
    if (conn->raop_rtp) {
        raop_rtp_flush(conn->raop_rtp, next_seq);
    } else {
        logger_log(raop->logger, LOGGER_WARNING, "RAOP not initialized at FLUSH");
    }
}

static void
raop_handler_teardown(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    /* get the teardown request type(s):  (type 96, 110, or none) */
    raop_t *raop = conn->raop;
    /* Disarm the classic path. Without this a TEARDOWN followed by a bodyless
       SETUP would rebuild a session from the previous ANNOUNCE's key and iv. */
    conn->classic_raop = false;
    const char *data = NULL;
    int data_len = 0;
    bool teardown_96 = false, teardown_110 = false;
    data = http_request_get_data(request, &data_len);
    plist_t req_root_node = NULL;
    plist_from_bin(data, data_len, &req_root_node);
    plist_t req_streams_node = plist_dict_get_item(req_root_node, "streams");
    /* Process stream teardown requests */
    if (PLIST_IS_ARRAY(req_streams_node)) {
        uint64_t val = 0;
        int count = plist_array_get_size(req_streams_node);
        for (int i = 0; i < count; i++) {
            plist_t req_stream_node = plist_array_get_item(req_streams_node,i);
            plist_t req_stream_type_node = plist_dict_get_item(req_stream_node, "type");
            plist_get_uint_val(req_stream_type_node, &val);
            if (val == 96) {
                teardown_96 = true;
            } else if (val == 110) { 
                teardown_110 = true;
            }
        }
    }
    plist_free(req_root_node);
    logger_log(raop->logger, LOGGER_DEBUG, "TEARDOWN request,  96=%d, 110=%d", teardown_96, teardown_110);
  
    http_response_add_header(response, "Connection", "close");
  
    if (teardown_96) {
        if (conn->raop_rtp) {
            /* Stop our audio RTP session */
            raop_rtp_stop(conn->raop_rtp);
            /* stop any  coverart rendering */
            if (raop->callbacks.audio_stop_coverart_rendering) {
                raop->callbacks.audio_stop_coverart_rendering(raop->callbacks.cls);
            }
        }
    } else if (teardown_110) {
        if (raop->hls_pending) {
            raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_RTP_TO_HLS_TEARDOWN);
        } else {
            raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_RTP_SHUTDOWN);
        }
        if (conn->raop_rtp_mirror) {
        /* Stop our video RTP session */
            raop_rtp_mirror_stop(conn->raop_rtp_mirror);
        }
    } else {
        /* Destroy our sessions */
        if (conn->raop_rtp) {
            raop_rtp_destroy(conn->raop_rtp);
            conn->raop_rtp = NULL;
        }
        if (conn->raop_rtp_mirror) {
            raop_rtp_mirror_destroy(conn->raop_rtp_mirror);
            conn->raop_rtp_mirror = NULL;
            /*fix for iOS >= 27 (does not send teardown_110 when mirrroring is stopped) */
            raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_RTP_SHUTDOWN);
        }
        /* shut down any HLS connections */
        int hls_count = httpd_count_connection_type(raop->httpd, CONNECTION_TYPE_HLS);
        if (hls_count) {
            raop->callbacks.video_reset(raop->callbacks.cls, RESET_TYPE_HLS_SHUTDOWN);
        }
    }
}
