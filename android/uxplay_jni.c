/*
 * UxPlay hosted in an Android app: JNI bridge between UxPlay's protocol
 * library (lib/) and org.lineageos.tv.airplay.UxPlay.
 *
 * lib/ does the AirPlay work -- pairing, FairPlay, decryption, NTP timing --
 * and hands over finished frames: Annex-B H.264/H.265 for video, ALAC or
 * AAC-ELD for audio, each with a presentation time in the local clock. This
 * file turns those into Java calls. It replaces uxplay.cpp and the GStreamer
 * renderers; the app decodes with MediaCodec and plays with AudioTrack.
 *
 * Two conversions happen here and nowhere else:
 *
 *  - Time. lib/'s local clock is CLOCK_REALTIME (raop_ntp_get_local_time).
 *    MediaCodec's timed release and System.nanoTime() are CLOCK_MONOTONIC, so
 *    every presentation time is shifted into that base before crossing JNI.
 *
 *  - ALAC. Android ships no ALAC decoder, so audio-only AirPlay (Apple Music
 *    and the like) is decoded here, with the decoder carried over from the
 *    shairport-sync port. AAC-ELD, which mirroring uses, goes up encoded:
 *    Android's own AAC decoder handles it.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "alac.h"
#include "dns_sd.h"
#include "dnssd.h"
#include "logger.h"
#include "raop.h"
#include "stream.h"

#define TAG "UxPlay"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* Defined in lib/raop.c; not in any header. */
extern uint64_t get_local_time(void);

static JavaVM *g_vm;
static pthread_key_t g_env_key;

/* Everything below is guarded by g_lock for start/stop; the callbacks read
   g_host only between a successful start and the matching stop. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static jobject g_host;
static raop_t *g_raop;
static dnssd_t *g_dnssd;

static jmethodID m_nsd_register, m_nsd_unregister;
static jmethodID m_conn_init, m_conn_destroy, m_conn_reset, m_client;
static jmethodID m_video_codec, m_video_frame, m_video_state, m_video_size, m_mirror_running;
static jmethodID m_audio_format, m_audio_pcm, m_audio_encoded, m_audio_flush, m_volume;
static jmethodID m_metadata, m_coverart, m_progress;

enum { VIDEO_PAUSE = 1, VIDEO_RESUME = 2, VIDEO_FLUSH = 3, VIDEO_RESET = 4 };

/* ------------------------------------------------------------ threads -- */

/* lib/ calls back on threads of its own. Each is attached once, on first
   use, and detached by the key's destructor when the thread exits. */
static void detach_on_exit(void *unused) {
    (void)unused;
    (*g_vm)->DetachCurrentThread(g_vm);
}

static JNIEnv *env_for_thread(void) {
    JNIEnv *env = NULL;
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK)
        return env;
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK)
        return NULL;
    pthread_setspecific(g_env_key, env);
    return env;
}

static bool check_exception(JNIEnv *env, const char *where) {
    if ((*env)->ExceptionCheck(env)) {
        ALOGE("exception in %s", where);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return true;
    }
    return false;
}

static jbyteArray to_bytes(JNIEnv *env, const void *data, int len) {
    jbyteArray arr = (*env)->NewByteArray(env, len);
    if (arr != NULL && len > 0)
        (*env)->SetByteArrayRegion(env, arr, 0, len, (const jbyte *)data);
    return arr;
}

/* --------------------------------------------------------------- time -- */

static int64_t clock_ns(clockid_t clock) {
    struct timespec t;
    clock_gettime(clock, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static pthread_mutex_t g_clock_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_remote_clock_offset;
static int g_open_connections;

/* The sender's clock mapped onto ours, fixed by the first frame of a
   connection, exactly as uxplay.cpp does. Then shifted from REALTIME to
   MONOTONIC for Java. */
static int64_t presentation_time_ns(uint64_t ntp_local, uint64_t ntp_remote) {
    pthread_mutex_lock(&g_clock_lock);
    if (g_remote_clock_offset == 0) {
        uint64_t local = ntp_local ? ntp_local : get_local_time();
        g_remote_clock_offset = local - ntp_remote;
    }
    uint64_t local_pts = ntp_remote + g_remote_clock_offset;
    pthread_mutex_unlock(&g_clock_lock);
    return (int64_t)local_pts - clock_ns(CLOCK_REALTIME) + clock_ns(CLOCK_MONOTONIC);
}

/* ---------------------------------------------------------------- mDNS -- */

static int nsd_register(const char *name, const char *regtype, uint16_t port, const uint8_t *txt,
                        uint16_t txt_len) {
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return kDNSServiceErr_ServiceNotRunning;
    jstring jname = (*env)->NewStringUTF(env, name);
    jstring jtype = (*env)->NewStringUTF(env, regtype);
    jbyteArray jtxt = to_bytes(env, txt, txt_len);
    jint id = (*env)->CallIntMethod(env, g_host, m_nsd_register, jname, jtype, (jint)port, jtxt);
    (*env)->DeleteLocalRef(env, jname);
    (*env)->DeleteLocalRef(env, jtype);
    (*env)->DeleteLocalRef(env, jtxt);
    if (check_exception(env, "nsdRegister"))
        return kDNSServiceErr_Unknown;
    return id;
}

static void nsd_unregister(int id) {
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_nsd_unregister, (jint)id);
    check_exception(env, "nsdUnregister");
}

/* --------------------------------------------------------- callbacks -- */

static void call_void(jmethodID m, const char *where) {
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m);
    check_exception(env, where);
}

static void cb_conn_init(void *cls) {
    (void)cls;
    pthread_mutex_lock(&g_clock_lock);
    g_open_connections++;
    pthread_mutex_unlock(&g_clock_lock);
    call_void(m_conn_init, "onConnInit");
}

static void cb_conn_destroy(void *cls) {
    (void)cls;
    pthread_mutex_lock(&g_clock_lock);
    if (--g_open_connections <= 0) {
        g_open_connections = 0;
        g_remote_clock_offset = 0; /* the next sender brings its own clock */
    }
    pthread_mutex_unlock(&g_clock_lock);
    call_void(m_conn_destroy, "onConnDestroy");
}

static void cb_conn_reset(void *cls, int reason) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_conn_reset, (jint)reason);
    check_exception(env, "onConnReset");
}

static void cb_conn_feedback(void *cls) { (void)cls; }

static void cb_report_client_request(void *cls, char *deviceid, char *model, char *name,
                                     bool *admit) {
    (void)cls;
    *admit = true; /* no access control yet; see pin_pw in uxplay.cpp */
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    jstring jname = (*env)->NewStringUTF(env, name ? name : "");
    jstring jmodel = (*env)->NewStringUTF(env, model ? model : "");
    jstring jid = (*env)->NewStringUTF(env, deviceid ? deviceid : "");
    (*env)->CallVoidMethod(env, g_host, m_client, jname, jmodel, jid);
    (*env)->DeleteLocalRef(env, jname);
    (*env)->DeleteLocalRef(env, jmodel);
    (*env)->DeleteLocalRef(env, jid);
    check_exception(env, "onClient");
}

static void cb_export_dacp(void *cls, const char *active_remote, const char *dacp_id) {
    (void)cls; (void)active_remote; (void)dacp_id;
}

static void cb_audio_remote_control_id(void *cls, const char *dacp_id,
                                       const char *active_remote_header) {
    (void)cls; (void)dacp_id; (void)active_remote_header;
}

/* ----- video */

static int cb_video_set_codec(void *cls, video_codec_t codec) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return -1;
    (*env)->CallVoidMethod(env, g_host, m_video_codec, (jboolean)(codec == VIDEO_CODEC_H265));
    check_exception(env, "onVideoCodec");
    return 0;
}

static void cb_video_process(void *cls, raop_ntp_t *ntp, video_decode_struct *data) {
    (void)cls; (void)ntp;
    /* lib/ marks a frame it could not decrypt by setting its first byte to 1;
       a good one starts with an Annex-B start code. */
    if (data->data_len <= 4 || data->data[0] != 0)
        return;
    int64_t pts = presentation_time_ns(data->ntp_time_local, data->ntp_time_remote);
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    jbyteArray frame = to_bytes(env, data->data, data->data_len);
    (*env)->CallVoidMethod(env, g_host, m_video_frame, frame, (jlong)pts,
                           (jboolean)data->is_h265);
    (*env)->DeleteLocalRef(env, frame);
    check_exception(env, "onVideoFrame");
}

static void video_state(int what, const char *where) {
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_video_state, (jint)what);
    check_exception(env, where);
}

static void cb_video_pause(void *cls) { (void)cls; video_state(VIDEO_PAUSE, "video_pause"); }
static void cb_video_resume(void *cls) { (void)cls; video_state(VIDEO_RESUME, "video_resume"); }
static void cb_video_flush(void *cls) { (void)cls; video_state(VIDEO_FLUSH, "video_flush"); }
static void cb_video_reset(void *cls, reset_type_t type) {
    (void)cls; (void)type;
    video_state(VIDEO_RESET, "video_reset");
}

static void cb_video_report_size(void *cls, float *width_source, float *height_source,
                                 float *width, float *height) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_video_size, (jint)*width_source, (jint)*height_source,
                           (jint)*width, (jint)*height);
    check_exception(env, "onVideoSize");
}

static void cb_mirror_video_running(void *cls, bool running) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_mirror_running, (jboolean)running);
    check_exception(env, "onMirrorRunning");
}

/* ----- audio */

static pthread_mutex_t g_alac_lock = PTHREAD_MUTEX_INITIALIZER;
static alac_file *g_alac;
static int g_alac_spf = 352;

/* The ALAC stream parameters AirPlay always uses: its fmtp line is
   "96 352 0 16 40 10 14 2 255 0 0 44100", which is also what uxplay.cpp's
   magic cookie encodes. */
static void alac_reset(int spf) {
    pthread_mutex_lock(&g_alac_lock);
    if (g_alac != NULL)
        alac_free(g_alac);
    g_alac = alac_create(16, 2);
    if (g_alac != NULL) {
        g_alac_spf = spf > 0 ? spf : 352;
        g_alac->setinfo_max_samples_per_frame = g_alac_spf;
        g_alac->setinfo_7a = 0;
        g_alac->setinfo_sample_size = 16;
        g_alac->setinfo_rice_historymult = 40;
        g_alac->setinfo_rice_initialhistory = 10;
        g_alac->setinfo_rice_kmodifier = 14;
        g_alac->setinfo_7f = 2;
        g_alac->setinfo_80 = 255;
        g_alac->setinfo_82 = 0;
        g_alac->setinfo_86 = 0;
        g_alac->setinfo_8a_rate = 44100;
        alac_allocate_buffers(g_alac);
    }
    pthread_mutex_unlock(&g_alac_lock);
}

static void cb_audio_get_format(void *cls, unsigned char *ct, unsigned short *spf,
                                bool *using_screen, bool *is_media, uint64_t *audio_format) {
    (void)cls; (void)audio_format;
    ALOGI("audio format: ct=%d spf=%d usingScreen=%d isMedia=%d", *ct, *spf, *using_screen,
          *is_media);
    if (*ct == 2)
        alac_reset(*spf);
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_audio_format, (jint)*ct, (jint)*spf,
                           (jboolean)*using_screen, (jboolean)*is_media);
    check_exception(env, "onAudioFormat");
}

static void cb_audio_process(void *cls, raop_ntp_t *ntp, audio_decode_struct *data) {
    (void)cls; (void)ntp;
    if (data->data_len <= 0)
        return;
    int64_t pts = presentation_time_ns(data->ntp_time_local, data->ntp_time_remote);
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;

    if (data->ct == 2) {
        /* ALAC -> interleaved 16-bit stereo, host order, which is what
           AudioTrack's ENCODING_PCM_16BIT wants. */
        int16_t pcm[4096 * 2];
        int out_bytes = sizeof(pcm);
        pthread_mutex_lock(&g_alac_lock);
        if (g_alac == NULL) {
            pthread_mutex_unlock(&g_alac_lock);
            return;
        }
        alac_decode_frame(g_alac, data->data, pcm, &out_bytes);
        pthread_mutex_unlock(&g_alac_lock);
        if (out_bytes <= 0)
            return;
        jbyteArray arr = to_bytes(env, pcm, out_bytes);
        (*env)->CallVoidMethod(env, g_host, m_audio_pcm, arr, (jlong)pts);
        (*env)->DeleteLocalRef(env, arr);
        check_exception(env, "onAudioPcm");
    } else {
        jbyteArray arr = to_bytes(env, data->data, data->data_len);
        (*env)->CallVoidMethod(env, g_host, m_audio_encoded, arr, (jlong)pts, (jint)data->ct);
        (*env)->DeleteLocalRef(env, arr);
        check_exception(env, "onAudioEncoded");
    }
}

static void cb_audio_flush(void *cls) { (void)cls; call_void(m_audio_flush, "onAudioFlush"); }

static double cb_audio_set_client_volume(void *cls) {
    (void)cls;
    return 0.0; /* full: the television's own volume is the real control */
}

static void cb_audio_set_volume(void *cls, float volume) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_volume, (jfloat)volume);
    check_exception(env, "onVolume");
}

static void bytes_callback(jmethodID m, const void *buffer, int len, const char *where) {
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    jbyteArray arr = buffer ? to_bytes(env, buffer, len) : NULL;
    (*env)->CallVoidMethod(env, g_host, m, arr);
    if (arr)
        (*env)->DeleteLocalRef(env, arr);
    check_exception(env, where);
}

static void cb_audio_set_metadata(void *cls, const void *buffer, int len) {
    (void)cls;
    bytes_callback(m_metadata, buffer, len, "onMetadata");
}

static void cb_audio_set_coverart(void *cls, const void *buffer, int len) {
    (void)cls;
    bytes_callback(m_coverart, buffer, len, "onCoverArt");
}

static void cb_audio_set_progress(void *cls, uint32_t *start, uint32_t *curr, uint32_t *end) {
    (void)cls;
    JNIEnv *env = env_for_thread();
    if (env == NULL || g_host == NULL)
        return;
    (*env)->CallVoidMethod(env, g_host, m_progress, (jlong)*start, (jlong)*curr, (jlong)*end);
    check_exception(env, "onProgress");
}

/* ----- logging */

static void log_callback(void *cls, int level, const char *msg) {
    (void)cls;
    int prio = level <= LOGGER_ERR       ? ANDROID_LOG_ERROR
               : level == LOGGER_WARNING ? ANDROID_LOG_WARN
               : level <= LOGGER_INFO    ? ANDROID_LOG_INFO
                                         : ANDROID_LOG_DEBUG;
    __android_log_write(prio, TAG, msg);
}

/* ------------------------------------------------------------- start -- */

static int parse_mac(const char *s, char out[6]) {
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        out[i] = (char)b[i];
    return 0;
}

/* uxplay.cpp's start_dnssd feature set, bits 0-31. Bits 32 and up stay at
   the defaults, as they do there. */
static void set_features(dnssd_t *d) {
    static const signed char bits[32] = {
        0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0,
    };
    for (int i = 0; i < 32; i++)
        dnssd_set_airplay_features(d, i, bits[i]);
}

static bool cache_methods(JNIEnv *env, jobject host) {
    jclass c = (*env)->GetObjectClass(env, host);
#define M(var, name, sig)                                  \
    if (!(var = (*env)->GetMethodID(env, c, name, sig))) { \
        ALOGE("missing method %s%s", name, sig);           \
        return false;                                      \
    }
    M(m_nsd_register, "nsdRegister", "(Ljava/lang/String;Ljava/lang/String;I[B)I");
    M(m_nsd_unregister, "nsdUnregister", "(I)V");
    M(m_conn_init, "onConnInit", "()V");
    M(m_conn_destroy, "onConnDestroy", "()V");
    M(m_conn_reset, "onConnReset", "(I)V");
    M(m_client, "onClient", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    M(m_video_codec, "onVideoCodec", "(Z)V");
    M(m_video_frame, "onVideoFrame", "([BJZ)V");
    M(m_video_state, "onVideoState", "(I)V");
    M(m_video_size, "onVideoSize", "(IIII)V");
    M(m_mirror_running, "onMirrorRunning", "(Z)V");
    M(m_audio_format, "onAudioFormat", "(IIZZ)V");
    M(m_audio_pcm, "onAudioPcm", "([BJ)V");
    M(m_audio_encoded, "onAudioEncoded", "([BJI)V");
    M(m_audio_flush, "onAudioFlush", "()V");
    M(m_volume, "onVolume", "(F)V");
    M(m_metadata, "onMetadata", "([B)V");
    M(m_coverart, "onCoverArt", "([B)V");
    M(m_progress, "onProgress", "(JJJ)V");
#undef M
    (*env)->DeleteLocalRef(env, c);
    return true;
}

static void stop_locked(void) {
    if (g_dnssd != NULL) {
        dnssd_unregister_raop(g_dnssd);
        dnssd_unregister_airplay(g_dnssd);
    }
    if (g_raop != NULL) {
        raop_destroy(g_raop); /* stops the server and its threads */
        g_raop = NULL;
    }
    if (g_dnssd != NULL) {
        dnssd_destroy(g_dnssd);
        g_dnssd = NULL;
    }
    pthread_mutex_lock(&g_alac_lock);
    if (g_alac != NULL) {
        alac_free(g_alac);
        g_alac = NULL;
    }
    pthread_mutex_unlock(&g_alac_lock);
    pthread_mutex_lock(&g_clock_lock);
    g_remote_clock_offset = 0;
    g_open_connections = 0;
    pthread_mutex_unlock(&g_clock_lock);
}

JNIEXPORT jint JNICALL Java_org_lineageos_tv_airplay_UxPlay_nativeStart(
        JNIEnv *env, jobject thiz, jstring jname, jstring jmac, jstring jkeyfile, jint width,
        jint height, jint refresh, jint max_fps) {
    pthread_mutex_lock(&g_lock);
    if (g_raop != NULL) {
        pthread_mutex_unlock(&g_lock);
        return raop_get_port(g_raop);
    }
    if (!cache_methods(env, thiz)) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    g_host = (*env)->NewGlobalRef(env, thiz);
    uxplay_dnssd_set_hooks(nsd_register, nsd_unregister);

    const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
    const char *mac = (*env)->GetStringUTFChars(env, jmac, NULL);
    const char *keyfile = (*env)->GetStringUTFChars(env, jkeyfile, NULL);
    int result = -1;

    char hw[6];
    if (parse_mac(mac, hw) != 0) {
        ALOGE("bad device id %s", mac);
        goto out;
    }

    int err = 0;
    g_dnssd = dnssd_init(name, strlen(name), hw, sizeof(hw), &err, 0 /* no pin */);
    if (err || g_dnssd == NULL) {
        ALOGE("dnssd_init failed: %d", err);
        goto fail;
    }
    set_features(g_dnssd);

    raop_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.conn_init = cb_conn_init;
    cbs.conn_destroy = cb_conn_destroy;
    cbs.conn_reset = cb_conn_reset;
    cbs.conn_feedback = cb_conn_feedback;
    cbs.audio_process = cb_audio_process;
    cbs.video_process = cb_video_process;
    cbs.audio_flush = cb_audio_flush;
    cbs.video_flush = cb_video_flush;
    cbs.video_pause = cb_video_pause;
    cbs.video_resume = cb_video_resume;
    cbs.video_reset = cb_video_reset;
    cbs.audio_set_client_volume = cb_audio_set_client_volume;
    cbs.audio_set_volume = cb_audio_set_volume;
    cbs.audio_get_format = cb_audio_get_format;
    cbs.video_report_size = cb_video_report_size;
    cbs.audio_set_metadata = cb_audio_set_metadata;
    cbs.audio_set_coverart = cb_audio_set_coverart;
    cbs.audio_set_progress = cb_audio_set_progress;
    cbs.audio_remote_control_id = cb_audio_remote_control_id;
    cbs.report_client_request = cb_report_client_request;
    cbs.export_dacp = cb_export_dacp;
    cbs.video_set_codec = cb_video_set_codec;
    cbs.mirror_video_running = cb_mirror_video_running;

    g_raop = raop_init(&cbs);
    if (g_raop == NULL) {
        ALOGE("raop_init failed");
        goto fail;
    }
    raop_set_log_callback(g_raop, log_callback, NULL);
    raop_set_log_level(g_raop, LOGGER_INFO);
    /* nohold: a new sender may take over from a connected one, which is what
       a shared television wants. */
    if (raop_init2(g_raop, 1, mac, keyfile)) {
        ALOGE("raop_init2 failed");
        goto fail;
    }
    if (width > 0) raop_set_plist(g_raop, "width", width);
    if (height > 0) raop_set_plist(g_raop, "height", height);
    if (refresh > 0) raop_set_plist(g_raop, "refreshRate", refresh);
    if (max_fps > 0) raop_set_plist(g_raop, "maxFPS", max_fps);

    unsigned short tcp[3] = {0, 0, 0}, udp[3] = {0, 0, 0}; /* 0: assigned */
    raop_set_tcp_ports(g_raop, tcp);
    raop_set_udp_ports(g_raop, udp);
    unsigned short port = raop_get_port(g_raop);
    if (raop_start_httpd(g_raop, &port) < 0) {
        ALOGE("could not start the AirPlay server");
        goto fail;
    }
    raop_set_port(g_raop, port);
    raop_set_dnssd(g_raop, g_dnssd);

    if (dnssd_register_raop(g_dnssd, port) != 0)
        ALOGW("could not advertise _raop._tcp");
    if (dnssd_register_airplay(g_dnssd, port) != 0)
        ALOGW("could not advertise _airplay._tcp");

    ALOGI("AirPlay server on port %u as \"%s\"", port, name);
    result = port;
    goto out;

fail:
    stop_locked();
    (*env)->DeleteGlobalRef(env, g_host);
    g_host = NULL;
out:
    (*env)->ReleaseStringUTFChars(env, jname, name);
    (*env)->ReleaseStringUTFChars(env, jmac, mac);
    (*env)->ReleaseStringUTFChars(env, jkeyfile, keyfile);
    pthread_mutex_unlock(&g_lock);
    return result;
}

JNIEXPORT void JNICALL Java_org_lineageos_tv_airplay_UxPlay_nativeStop(JNIEnv *env, jobject thiz) {
    (void)thiz;
    pthread_mutex_lock(&g_lock);
    stop_locked();
    if (g_host != NULL) {
        (*env)->DeleteGlobalRef(env, g_host);
        g_host = NULL;
    }
    uxplay_dnssd_set_hooks(NULL, NULL);
    pthread_mutex_unlock(&g_lock);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    pthread_key_create(&g_env_key, detach_on_exit);
    return JNI_VERSION_1_6;
}
