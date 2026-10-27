#include "tls_audit.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void copy_str(char *dst, size_t n, const char *src)
{
    size_t len = strlen(src);

    if (n == 0)
        return;
    if (len >= n)
        len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int contains_ci(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);

    if (nl == 0)
        return 0;
    for (; *hay != '\0'; hay++) {
        size_t i = 0;

        while (i < nl && hay[i] != '\0' &&
               tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl)
            return 1;
    }
    return 0;
}

/* ---------- SPKI blocklist ---------- */

static void to_hex(const unsigned char *b, size_t n, char *out)
{
    static const char dig[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = dig[b[i] >> 4];
        out[2 * i + 1] = dig[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static int bl_push(spki_blocklist *bl, const char *hex)
{
    if (bl->n == bl->cap) {
        size_t ncap = bl->cap ? bl->cap * 2 : 32;
        char (*nh)[65] = realloc(bl->hash, ncap * sizeof *nh);

        if (nh == NULL)
            return -1;
        bl->hash = nh;
        bl->cap = ncap;
    }
    copy_str(bl->hash[bl->n], 65, hex);
    bl->n++;
    return 0;
}

int spki_blocklist_load(const char *path, spki_blocklist *bl)
{
    FILE *f = fopen(path, "r");
    char line[512];

    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f) != NULL) {
        char *p = line;
        char *e;
        size_t len, i;

        while (isspace((unsigned char)*p))
            p++;
        if (*p == '#' || *p == '\0')
            continue;
        e = p;
        while (*e != '\0' && !isspace((unsigned char)*e))
            e++;
        len = (size_t)(e - p);
        *e = '\0';
        if (len == 64) {
            int ok = 1;

            for (i = 0; i < 64; i++)
                if (!isxdigit((unsigned char)p[i]))
                    ok = 0;
            if (ok) {
                for (i = 0; i < 64; i++)
                    p[i] = (char)tolower((unsigned char)p[i]);
                if (bl_push(bl, p) != 0) {
                    fclose(f);
                    return -1;
                }
            }
        } else if (len == 44 && p[43] == '=') { /* base64 of 32 bytes */
            unsigned char raw[48];
            char hex[65];
            int n = EVP_DecodeBlock(raw, (const unsigned char *)p, 44);

            if (n == 33) { /* 32 bytes + 1 padding byte counted by EVP_DecodeBlock */
                to_hex(raw, 32, hex);
                if (bl_push(bl, hex) != 0) {
                    fclose(f);
                    return -1;
                }
            }
        }
    }
    fclose(f);
    return 0;
}

int spki_blocklist_has(const spki_blocklist *bl, const char *hex)
{
    size_t i;

    for (i = 0; i < bl->n; i++)
        if (strcmp(bl->hash[i], hex) == 0)
            return 1;
    return 0;
}

void spki_blocklist_free(spki_blocklist *bl)
{
    free(bl->hash);
    memset(bl, 0, sizeof *bl);
}

/* ---------- interception detection ---------- */

const char *tls_detect_interception(const char *s)
{
    static const char *const names[] = {
        "Norton Web/Mail Shield", "Kaspersky", "ESET SSL Filter", "Avast Web/Mail Shield",
        "AVG Web/Mail Shield", "Bitdefender", "Zscaler", "Fortinet", "Sophos", "Cisco Umbrella",
        "Blue Coat", "mitmproxy", "Fiddler", NULL};
    int i;

    for (i = 0; names[i] != NULL; i++)
        if (contains_ci(s, names[i]))
            return names[i];
    return NULL;
}

/* ---------- OpenSSL helpers ---------- */

SSL_CTX *tls_new_client_ctx(const char *ca_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_security_level(ctx, 0); /* audit tool: talk to legacy servers and report them */
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (ca_file != NULL) {
        SSL_CTX_load_verify_locations(ctx, ca_file, NULL);
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
#ifdef _WIN32
        /* MSYS2's OpenSSL looks for roots under "/ucrt64/etc/ssl", which is empty or missing on
           a normal Windows PC, so every chain failed with code 20. OpenSSL >= 3.2 can read the
           Windows root store (the one Edge uses); older versions just skip this. */
        if (SSL_CTX_load_verify_store(ctx, "org.openssl.winstore://") != 1)
            ERR_clear_error();
#endif
    }
    return ctx;
}

SSL *tls_handshake(SSL_CTX *ctx, net_sock s, const char *host, int want_ocsp, char *err,
                   size_t errlen)
{
    SSL *ssl = SSL_new(ctx);

    if (ssl == NULL) {
        copy_str(err, errlen, "SSL_new failed");
        return NULL;
    }
    SSL_set_fd(ssl, (int)s);
    if (host != NULL) {
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set1_host(ssl, host);
    }
    if (want_ocsp)
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
        char msg[120] = "TLS handshake failed";

        if (e != 0)
            ERR_error_string_n(e, msg, sizeof msg);
        copy_str(err, errlen, msg);
        ERR_clear_error();
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

static void bio_str(BIO *b, char *out, size_t n)
{
    char *p = NULL;
    long len = BIO_get_mem_data(b, &p);

    if (len < 0 || p == NULL)
        len = 0;
    if ((size_t)len >= n)
        len = (long)n - 1;
    memcpy(out, p, (size_t)len);
    out[len] = '\0';
}

static void name_str(const X509_NAME *nm, char *out, size_t n)
{
    BIO *b = BIO_new(BIO_s_mem());

    out[0] = '\0';
    if (b == NULL)
        return;
    X509_NAME_print_ex(b, nm, 0, XN_FLAG_RFC2253);
    bio_str(b, out, n);
    BIO_free(b);
}

static void time_str(const ASN1_TIME *t, char *out, size_t n)
{
    BIO *b = BIO_new(BIO_s_mem());

    out[0] = '\0';
    if (b == NULL)
        return;
    ASN1_TIME_print(b, t);
    bio_str(b, out, n);
    BIO_free(b);
}

static void first_crl_url(X509 *x, char *out, size_t n)
{
    CRL_DIST_POINTS *cdp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    int i, j;

    out[0] = '\0';
    if (cdp == NULL)
        return;
    for (i = 0; i < sk_DIST_POINT_num(cdp) && out[0] == '\0'; i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(cdp, i);

        if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0)
            continue;
        for (j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);

            if (gn->type == GEN_URI) {
                const ASN1_IA5STRING *u = gn->d.uniformResourceIdentifier;

                copy_str(out, n, (const char *)ASN1_STRING_get0_data(u));
                break;
            }
        }
    }
    CRL_DIST_POINTS_free(cdp);
}

static void fill_cert(X509 *x, const adv_list *adv, const spki_blocklist *bl, tls_cert_info *c)
{
    EVP_PKEY *pk;
    unsigned char *der = NULL;
    unsigned char md[SHA256_DIGEST_LENGTH];
    int dlen, days = 0, secs = 0;
    STACK_OF(OPENSSL_STRING) *ocsp;
    size_t k;

    memset(c, 0, sizeof *c);
    name_str(X509_get_subject_name(x), c->subject, sizeof c->subject);
    name_str(X509_get_issuer_name(x), c->issuer, sizeof c->issuer);

    pk = X509_get0_pubkey(x);
    if (pk != NULL) {
        int id = EVP_PKEY_base_id(pk);

        c->key_bits = EVP_PKEY_bits(pk);
        copy_str(c->key_alg, sizeof c->key_alg,
                 id == EVP_PKEY_RSA ? "RSA" : id == EVP_PKEY_EC ? "EC"
                 : id == EVP_PKEY_ED25519 ? "Ed25519" : id == EVP_PKEY_DSA ? "DSA" : "other");
        if (id == EVP_PKEY_RSA && c->key_bits < 2048)
            c->flags |= TLSF_WEAK_KEY;
    }
    time_str(X509_get0_notBefore(x), c->not_before, sizeof c->not_before);
    time_str(X509_get0_notAfter(x), c->not_after, sizeof c->not_after);
    if (ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(x)) == 1) {
        c->days_left = days;
        if (days < 0 || (days == 0 && secs < 0))
            c->flags |= TLSF_EXPIRED;
        else if (days <= 14)
            c->flags |= TLSF_EXPIRES_SOON;
    }
    if (X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) == 0)
        c->flags |= TLSF_SELF_SIGNED;

    dlen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &der);
    if (dlen > 0 && der != NULL) {
        SHA256(der, (size_t)dlen, md);
        to_hex(md, sizeof md, c->spki_sha256);
        if (bl != NULL && spki_blocklist_has(bl, c->spki_sha256))
            c->flags |= TLSF_BLOCKLISTED;
    }
    OPENSSL_free(der);

    ocsp = X509_get1_ocsp(x);
    if (ocsp != NULL) {
        if (sk_OPENSSL_STRING_num(ocsp) > 0)
            copy_str(c->ocsp_url, sizeof c->ocsp_url, sk_OPENSSL_STRING_value(ocsp, 0));
        X509_email_free(ocsp);
    }
    first_crl_url(x, c->crl_url, sizeof c->crl_url);

    for (k = 0; adv != NULL && k < adv->n; k++) {
        const adv_entry *e = &adv->e[k];
        char buf[192];
        char *tok, *next;

        if (strcmp(e->module, "tls") != 0 || strcmp(e->product, "issuer-name") != 0)
            continue;
        copy_str(buf, sizeof buf, e->fixed);
        for (tok = buf; tok != NULL; tok = next) {
            next = strchr(tok, ';');
            if (next != NULL)
                *next++ = '\0';
            if (tok[0] != '\0' && (contains_ci(c->subject, tok) || contains_ci(c->issuer, tok))) {
                c->flags |= TLSF_ISSUER_MATCH;
                copy_str(c->matched, sizeof c->matched, tok);
                return;
            }
        }
    }
}

static void read_stapled_ocsp(SSL *ssl, tls_result *out)
{
    unsigned char *raw = NULL;
    const unsigned char *rp;
    long rl = SSL_get_tlsext_status_ocsp_resp(ssl, &raw);
    OCSP_RESPONSE *oresp;

    copy_str(out->ocsp_status, sizeof out->ocsp_status, "none stapled by the server");
    if (rl <= 0 || raw == NULL)
        return;
    out->ocsp_stapled = 1;
    rp = raw;
    oresp = d2i_OCSP_RESPONSE(NULL, &rp, rl);
    if (oresp == NULL) {
        copy_str(out->ocsp_status, sizeof out->ocsp_status, "stapled but unparsable");
        return;
    }
    if (OCSP_response_status(oresp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        copy_str(out->ocsp_status, sizeof out->ocsp_status, "stapled, responder reported an error");
    } else {
        OCSP_BASICRESP *br = OCSP_response_get1_basic(oresp);

        if (br != NULL && OCSP_resp_count(br) > 0) {
            int reason = 0;
            ASN1_GENERALIZEDTIME *rev = NULL, *tu = NULL, *nu = NULL;
            int cs = OCSP_single_get0_status(OCSP_resp_get0(br, 0), &reason, &rev, &tu, &nu);

            snprintf(out->ocsp_status, sizeof out->ocsp_status,
                     "stapled: %s (response signature NOT verified here)",
                     cs == V_OCSP_CERTSTATUS_GOOD ? "good"
                     : cs == V_OCSP_CERTSTATUS_REVOKED ? "REVOKED" : "unknown");
        } else {
            copy_str(out->ocsp_status, sizeof out->ocsp_status, "stapled, empty response");
        }
        OCSP_BASICRESP_free(br);
    }
    OCSP_RESPONSE_free(oresp);
}

int tls_audit_host(const char *host, unsigned short port, int timeout_ms, const char *ca_file,
                   const adv_list *adv, const spki_blocklist *bl, tls_result *out)
{
    char portstr[8];
    net_sock s;
    SSL_CTX *ctx;
    SSL *ssl;
    STACK_OF(X509) *chain;
    X509 *single = NULL;
    int i, n;

    memset(out, 0, sizeof *out);
    copy_str(out->host, sizeof out->host, host);
    out->port = port;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    if (net_init() != 0) {
        copy_str(out->error, sizeof out->error, "network init failed");
        return -1;
    }
    s = net_connect(host, portstr, timeout_ms, out->error, sizeof out->error);
    if (s == NET_BAD)
        return -1;
    ctx = tls_new_client_ctx(ca_file);
    if (ctx == NULL) {
        copy_str(out->error, sizeof out->error, "cannot create TLS context");
        net_close(s);
        return -1;
    }
    ssl = tls_handshake(ctx, s, host, 1, out->error, sizeof out->error);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        net_close(s);
        return -1;
    }
    out->connected = 1;
    copy_str(out->protocol, sizeof out->protocol, SSL_get_version(ssl));
    copy_str(out->cipher, sizeof out->cipher, SSL_get_cipher_name(ssl));
    out->verify_code = SSL_get_verify_result(ssl);
    copy_str(out->verify_text, sizeof out->verify_text,
             X509_verify_cert_error_string(out->verify_code));

    chain = SSL_get_peer_cert_chain(ssl);
    n = chain != NULL ? sk_X509_num(chain) : 0;
    if (n == 0) { /* fall back to the leaf alone */
        single = SSL_get1_peer_certificate(ssl);
        if (single != NULL) {
            fill_cert(single, adv, bl, &out->certs[0]);
            out->ncerts = 1;
        }
    }
    for (i = 0; i < n && i < TLS_MAX_CERTS; i++) {
        fill_cert(sk_X509_value(chain, i), adv, bl, &out->certs[i]);
        out->ncerts++;
    }
    X509_free(single);
    for (i = 0; i < out->ncerts && out->interception[0] == '\0'; i++) {
        const char *who = tls_detect_interception(out->certs[i].issuer);

        if (who == NULL)
            who = tls_detect_interception(out->certs[i].subject);
        if (who != NULL)
            copy_str(out->interception, sizeof out->interception, who);
    }
    read_stapled_ocsp(ssl, out);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    net_close(s);
    return 0;
}

int tls_protocol_is_weak(const char *protocol)
{
    /* SSL_get_version names TLS 1.0 "TLSv1", so match it exactly, not as a prefix of 1.2/1.3 */
    return strcmp(protocol, "TLSv1") == 0 || strncmp(protocol, "TLSv1.0", 7) == 0 ||
           strncmp(protocol, "TLSv1.1", 7) == 0 || strncmp(protocol, "SSL", 3) == 0;
}

void tls_result_print(const tls_result *r, FILE *out)
{
    int i;

    fprintf(out, "%s:%u  ", r->host, (unsigned)r->port);
    if (!r->connected) {
        fprintf(out, "no result: %s\n", r->error[0] ? r->error : "unknown error");
        return;
    }
    fprintf(out, "%s  %s\n", r->protocol, r->cipher);
    if (r->interception[0] != '\0')
        fprintf(out,
                "!! TLS INSPECTION DETECTED (%s): the chain below was re-signed on this machine/"
                "network, so it is NOT the server's real certificate chain. Run the audit from a "
                "machine without HTTPS scanning (or pause it) for a meaningful result.\n",
                r->interception);
    if (tls_protocol_is_weak(r->protocol))
        fprintf(out, "!! weak protocol negotiated: %s\n", r->protocol);
    fprintf(out, "Certificate chain presented (%d):\n", r->ncerts);
    for (i = 0; i < r->ncerts; i++) {
        const tls_cert_info *c = &r->certs[i];

        fprintf(out, " [%d] subject: %s\n     issuer:  %s\n", i, c->subject, c->issuer);
        fprintf(out, "     key: %s %d bits   valid: %s  ->  %s  (%ld days left)\n", c->key_alg,
                c->key_bits, c->not_before, c->not_after, c->days_left);
        fprintf(out, "     spki-sha256: %s\n", c->spki_sha256);
        if (c->flags & TLSF_EXPIRED)
            fprintf(out, "     !! EXPIRED\n");
        if (c->flags & TLSF_EXPIRES_SOON)
            fprintf(out, "     !! expires within 14 days\n");
        if (c->flags & TLSF_SELF_SIGNED)
            fprintf(out, "     note: self-signed (subject == issuer)\n");
        if (c->flags & TLSF_WEAK_KEY)
            fprintf(out, "     !! weak RSA key (< 2048 bits)\n");
        if (c->flags & TLSF_BLOCKLISTED)
            fprintf(out, "     !! SPKI hash is in your blocklist (known-compromised key)\n");
        if (c->flags & TLSF_ISSUER_MATCH)
            fprintf(out, "     !! name matches advisory issuer '%s' (see data/advisories.txt)\n",
                    c->matched);
        if (c->ocsp_url[0])
            fprintf(out, "     OCSP responder: %s\n", c->ocsp_url);
        if (c->crl_url[0])
            fprintf(out, "     CRL: %s\n", c->crl_url);
    }
    fprintf(out, "Trust check (OpenSSL roots, plus the Windows root store on Windows): %s (code %ld)\n",
            r->verify_text, r->verify_code);
    fprintf(out, "Stapled OCSP: %s\n", r->ocsp_status);
    fprintf(out, "Not checked: live OCSP/CRL lookups (URLs are only listed), certificate "
                 "transparency, and keys not in your blocklist. A clean result is not proof.\n");
}
