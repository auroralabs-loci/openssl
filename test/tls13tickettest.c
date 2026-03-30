/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>
#include "helpers/ssltestlib.h"
#include "testutil.h"

/*
 * Do not issue TLS 1.3 session tickets if the server has explicitly disabled
 * them via SSL_OP_NO_TICKET and also disabled the session cache with
 * SSL_SESS_CACHE_OFF. Together, these settings clearly indicate an intent to
 * suppress session resumption; sending NewSessionTicket messages in this case
 * would be wasteful and misleading.
 *
 * From the server’s perspective, a client that does not advertise
 * psk_key_exchange_modes in TLS 1.3, or that sends it with RFC 9149 parameters
 * such as new_session_count = 0 or resumption_count = 0, is effectively
 * signaling no interest in session tickets or resumption.
 *
 * This should be interpreted consistently with TLS 1.2 and earlier versions,
 * as well as TLS 1.3 in middlebox compatibility mode, where the presence of
 * the session_ticket extension indicates a desire to use tickets. If no such
 * signal is present, the server should refrain from issuing tickets.
 *
 * Notably, when both SSL_OP_NO_TICKET and SSL_SESS_CACHE_OFF are set on the
 * client side, the client omits psk_key_exchange_modes in TLS 1.3, does not
 * include the session_ticket (35) extension in TLS 1.3 middlebox compatibility
 * mode, and similarly omits ticket signaling in older protocol versions.
 */

struct stats {
    unsigned int tickets;
    unsigned int nst_msgs;
    unsigned int ch_has_psk;
    unsigned int ch_has_psk_kex_modes;
    unsigned int ch_has_session_ticket;
    unsigned int sh_has_psk;
    unsigned int sh_has_supported_versions;
};

struct tls13_endpoint {
    SSL *ssl;
    struct stats stats;
};

struct tls13_channel {
    struct tls13_endpoint c, s;
};

static char *cert = NULL;
static char *pkey = NULL;
static int stats_idx = -1;

static int sess_new_cb(SSL *ssl, SSL_SESSION *session)
{
    struct stats *stats = SSL_get_ex_data(ssl, stats_idx);
    if (stats == NULL)
        return 0;
    if (SSL_is_init_finished(ssl) == 0)
        stats->tickets++;
    return 0;
}

static void handshake_finished(const SSL *ssl)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";
    if (SSL_session_reused(ssl))
        TEST_info("%s: Abbreviated handshake finished", endpoint);
    else
        TEST_info("%s: Full handshake finished", endpoint);
}

static void info_cb(const SSL *ssl, int type, int val)
{
    const char *endpoint = SSL_is_server(ssl) ? "server" : "client";

    if (type & SSL_CB_ALERT) {
        const char *dir = (type & SSL_CB_READ) ? "read" : "write";

        TEST_info("%s: alert %s: %s : %s", endpoint, dir,
            SSL_alert_type_string_long(val),
            SSL_alert_desc_string_long(val));
    }
    if (type & SSL_CB_HANDSHAKE_DONE)
        handshake_finished(ssl);
}

static int has_extension(const unsigned char *ex, size_t len, unsigned int type)
{
    while (len >= 4) {
        size_t size = (ex[2] << 8) | ex[3];

        if (len < 4 + size)
            break;
        if ((unsigned int)(((ex[0] << 8) | ex[1])) == type)
            return 1;
        ex += 4 + size;
        len -= 4 + size;
    }
    return 0;
}

static void parse_ch_exts(const unsigned char *buf, size_t len, struct stats *x)
{
    size_t off = 4, sid_len, cs_len, comp_len, ext_len;

    if (len < off + 2 + 32)
        return;
    off += 2 + 32;
    if (len < off + 1)
        return;
    sid_len = buf[off];
    off += 1 + sid_len;
    if (len < off + 2)
        return;
    cs_len = (buf[off] << 8) | buf[off + 1];
    off += 2 + cs_len;
    if (len < off + 1)
        return;
    comp_len = buf[off];
    off += 1 + comp_len;
    if (len < off + 2)
        return;
    ext_len = (buf[off] << 8) | buf[off + 1];
    off += 2;
    if (len < off + ext_len)
        return;

    x->ch_has_psk = has_extension(buf + off, ext_len, TLSEXT_TYPE_psk);
    x->ch_has_psk_kex_modes = has_extension(buf + off, ext_len,
        TLSEXT_TYPE_psk_kex_modes);
    x->ch_has_session_ticket = has_extension(buf + off, ext_len,
        TLSEXT_TYPE_session_ticket);
    TEST_info("ch extensions: psk=%d psk_kex_modes=%d session_ticket=%d",
        x->ch_has_psk, x->ch_has_psk_kex_modes, x->ch_has_session_ticket);
}

static void parse_sh_exts(const unsigned char *buf, size_t len, struct stats *x)
{
    size_t off = 4, sid_len, ext_len;

    if (len < off + 2 + 32 + 1)
        return;
    off += 2 + 32;
    sid_len = buf[off];
    off += 1 + sid_len;
    if (len < off + 2 + 1)
        return;
    off += 2 + 1;
    if (len < off + 2)
        return;
    ext_len = (buf[off] << 8) | buf[off + 1];
    off += 2;
    if (len < off + ext_len)
        return;

    x->sh_has_psk = has_extension(buf + off, ext_len, TLSEXT_TYPE_psk);
    x->sh_has_supported_versions = has_extension(buf + off, ext_len,
        TLSEXT_TYPE_supported_versions);
    TEST_info("sh extensions: psk=%d supported_versions=%d",
        x->sh_has_psk, x->sh_has_supported_versions);
}

static void msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    struct stats *stats = SSL_get_ex_data(ssl, stats_idx);

    if (content_type == SSL3_RT_HANDSHAKE && len > 0) {
        unsigned char mt = ((const unsigned char *)buf)[0];

        if (mt == SSL3_MT_NEWSESSION_TICKET && stats != NULL)
            stats->nst_msgs++;
        if (mt == SSL3_MT_CLIENT_HELLO && stats != NULL)
            parse_ch_exts(buf, len, stats);
        if (mt == SSL3_MT_SERVER_HELLO && stats != NULL)
            parse_sh_exts(buf, len, stats);
    }
}

static int set_ctx_callbacks(SSL_CTX *c, SSL_CTX *s)
{
    SSL_CTX_sess_set_new_cb(s, sess_new_cb);
    SSL_CTX_sess_set_new_cb(c, sess_new_cb);
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    return 1;
}

static int tls_channel_init(SSL_CTX *c_ctx, SSL_CTX *s_ctx, struct tls13_channel *ch)
{
    SSL *c = NULL, *s = NULL;
    int test;

    memset(ch, 0, sizeof(*ch));

    test = TEST_true(create_ssl_objects(s_ctx, c_ctx, &s, &c, NULL, NULL))
        && TEST_true(SSL_set_ex_data(c, stats_idx, &ch->c.stats))
        && TEST_true(SSL_set_ex_data(s, stats_idx, &ch->s.stats));

    if (test != 0) {
        SSL_set_info_callback(c, info_cb);
        SSL_set_msg_callback(c, msg_cb);
        SSL_set_info_callback(s, info_cb);
        SSL_set_msg_callback(s, msg_cb);
        ch->c.ssl = c;
        ch->s.ssl = s;
    }
    return test;
}

static void tls_channel_fini(struct tls13_channel *ch)
{
    SSL_free(ch->c.ssl);
    SSL_free(ch->s.ssl);
}

static int tls_shutdown(struct tls13_channel *ch)
{
    SSL_set_shutdown(ch->c.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_set_shutdown(ch->s.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    return 1;
}

static int ticket_enable(SSL_CTX *ctx)
{
    unsigned flags = SSL_SESS_CACHE_NO_INTERNAL_STORE;
    if (SSL_CTX_is_server(ctx))
        flags |= SSL_SESS_CACHE_SERVER;
    else
        flags |= SSL_SESS_CACHE_CLIENT;

    SSL_CTX_set_session_cache_mode(ctx, flags);
    return 1;
}

static int ticket_disable(SSL_CTX *ctx)
{
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return 1;
}

static int test_tls12_ticket_enable(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 1)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 1)
        && TEST_uint_eq(initial.c.stats.tickets, 1)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 0)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 0);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls12_ticket_disable_server(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_disable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 0);

    tls_channel_fini(&initial);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls12_ticket_disable_client(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_2_VERSION, TLS1_2_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_disable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 0)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 0);

    tls_channel_fini(&initial);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Verify ticket regeneration after fallback to a full handshake. If session
 * resumption fails due to a ciphersuite mismatch, it falls back to a full
 * handshake. In that case, ensure a new session ticket is issued reflecting the
 * negotiated ciphersuite.
 */
static int test_tls13_ticket_ciphersuite_mismatch(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_128_GCM_SHA256"))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_uint_ge(initial.c.stats.tickets, 1)
        && TEST_true(tls_shutdown(&initial))
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_ciphersuites(s, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(SSL_CTX_set_ciphersuites(c, "TLS_AES_256_GCM_SHA384"))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.tickets, 2)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * NOTE: It has been observed that even when SSL_OP_ENABLE_MIDDLEBOX_COMPAT
 * is explicitly disabled, the session_ticket extension (#35) is still present
 * in the ClientHello for channels where both min and max protocol version are
 * TLS 1.3. This is unexpected given that session_ticket (#35) is defined as
 * TLS1_2_AND_BELOW_ONLY in OpenSSL, and therefore should not appear in a
 * strictly TLS 1.3 handshake with middlebox compat disabled. This warrants
 * further investigation, it may indicate that OpenSSL emits this extension
 * independently of middlebox compat mode under certain conditions. This
 * remains an open question and a basis for a follow-up analysis.
 */

static int test_tls13_ticket_enable(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(SSL_CTX_clear_options(c, SSL_OP_ENABLE_MIDDLEBOX_COMPAT))
        && TEST_true(SSL_CTX_clear_options(s, SSL_OP_ENABLE_MIDDLEBOX_COMPAT))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls13_ticket_enable_middlebox_compat(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(SSL_CTX_set_options(c, SSL_OP_ENABLE_MIDDLEBOX_COMPAT))
        && TEST_true(SSL_CTX_set_options(s, SSL_OP_ENABLE_MIDDLEBOX_COMPAT))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.tickets, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * If num_tickets is set to 0, then no tickets will be issued for either
 * a full (initial) connection or a resumed session. In this case, even
 * in TLS 1.3 with middlebox compatibility mode enabled, the
 * ticket_session extension should not be present in ServerHello, since
 * there is no intention to issue any tickets.
 *
 * This is also a possible rationale for the following draft/PR.
 */
static int test_tls13_ticket_initial_set_num_tickets_zero(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls13_ticket_resumed_set_num_tickets_zero(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 2)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_true(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Do not issue TLSv1.3 session tickets if the server has explicitly disabled
 * them via SSL_OP_NO_TICKET and also turned off the session cache with
 * SSL_SESS_CACHE_OFF. Both conditions together indicate a clear intent to
 * suppress resumption, so sending NewSessionTicket messages would be
 * wasteful and misleading.
 */
static int test_tls13_ticket_disable_server(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_disable(s))
        && TEST_true(ticket_enable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 1)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 1)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

/*
 * Do not request or accept TLSv1.3 session tickets if the client has set
 * both SSL_OP_NO_TICKET and SSL_SESS_CACHE_OFF. When both are set, the
 * client has no session cache to store tickets in and no intention to
 * resume.
 *
 * From the server's perspective, a client that does not send the
 * psk_key_exchange_modes extension or that sends it together with RFC 9149
 * parameters such as new_session_count = 0; or resumption_count = 0; is
 * effectively signaling no interest in session tickets or session resumption,
 * and in all such cases the server should interpret this equivalently and
 * refrain from issuing tickets.
 *
 * The session_ticket extension (#35) is defined as TLS1_2_AND_BELOW_ONLY,
 * however in TLS 1.3 MIDDLEBOX_COMPAT mode (which is enabled by default
 * in OpenSSL) the client sends it as an empty decoy to maintain compatibility
 * with middleboxes. Actual session resumption is handled via PSK/pre_shared_key
 * (#41).
 *
 * However, if the client explicitly signals no interest in session tickets
 * and resumption (e.g. SSL_OP_NO_TICKET), session_ticket should not be
 * present in the ClientHello. We therefore check for the presence of this
 * extension here even if the negotiated min/max protocol version is TLS 1.3.
 *
 * Signal zero ticket desire to the server using the ticket_request extension
 * [RFC-9149] if supported.
 */
static int test_tls13_ticket_disable_client(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_enable(s))
        && TEST_true(ticket_disable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

static int test_tls13_ticket_disable_both(void)
{
    SSL_CTX *c = NULL, *s = NULL;
    struct tls13_channel initial = { .c.ssl = NULL, .s.ssl = NULL };
    struct tls13_channel resumed = { .c.ssl = NULL, .s.ssl = NULL };
    SSL_SESSION *sess = NULL;
    int test;

    test = TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, &s, &c, cert, pkey))
        && TEST_true(set_ctx_callbacks(c, s))
        && TEST_true(ticket_disable(s))
        && TEST_true(ticket_disable(c))
        && TEST_true(tls_channel_init(c, s, &initial))
        && TEST_true(create_ssl_connection(initial.s.ssl, initial.c.ssl, SSL_ERROR_NONE))
        && TEST_true(tls_shutdown(&initial))
        && TEST_uint_eq(initial.s.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.nst_msgs, 0)
        && TEST_uint_eq(initial.c.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.tickets, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(initial.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(initial.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(initial.s.stats.sh_has_supported_versions, 1)
        && TEST_ptr(sess = SSL_get1_session(initial.c.ssl))
        && TEST_true(SSL_CTX_set_num_tickets(s, 0))
        && TEST_true(tls_channel_init(c, s, &resumed))
        && TEST_true(SSL_set_session(resumed.c.ssl, sess))
        && TEST_true(create_ssl_connection(resumed.s.ssl, resumed.c.ssl, SSL_ERROR_NONE))
        && TEST_false(SSL_session_reused(resumed.c.ssl))
        && TEST_uint_eq(resumed.s.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.nst_msgs, 0)
        && TEST_uint_eq(resumed.c.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.tickets, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_session_ticket, 0)
        && TEST_uint_eq(resumed.s.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.ch_has_psk_kex_modes, 0)
        && TEST_uint_eq(resumed.c.stats.sh_has_supported_versions, 1)
        && TEST_uint_eq(resumed.s.stats.sh_has_supported_versions, 1);

    SSL_SESSION_free(sess);
    tls_channel_fini(&initial);
    tls_channel_fini(&resumed);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
    return test;
}

OPT_TEST_DECLARE_USAGE("\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(pkey = test_get_argument(1)))
        return 0;

    stats_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ADD_TEST(test_tls12_ticket_enable);
    ADD_TEST(test_tls12_ticket_disable_server);
    ADD_TEST(test_tls12_ticket_disable_client);
    ADD_TEST(test_tls13_ticket_ciphersuite_mismatch);
    ADD_TEST(test_tls13_ticket_enable);
    ADD_TEST(test_tls13_ticket_enable_middlebox_compat);
    ADD_TEST(test_tls13_ticket_initial_set_num_tickets_zero);
    ADD_TEST(test_tls13_ticket_resumed_set_num_tickets_zero);
    ADD_TEST(test_tls13_ticket_disable_server);
    ADD_TEST(test_tls13_ticket_disable_client);
    ADD_TEST(test_tls13_ticket_disable_both);

    return 1;
}
