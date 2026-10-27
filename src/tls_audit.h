#ifndef TLS_AUDIT_H
#define TLS_AUDIT_H

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdio.h>

#include "advisory.h"
#include "net_compat.h"

#define TLS_MAX_CERTS 10

/* flag bits for tls_cert_info.flags */
#define TLSF_EXPIRED 1u
#define TLSF_EXPIRES_SOON 2u /* within 14 days */
#define TLSF_SELF_SIGNED 4u
#define TLSF_WEAK_KEY 8u     /* RSA < 2048 bits */
#define TLSF_BLOCKLISTED 16u /* SPKI hash is in the user's blocklist */
#define TLSF_ISSUER_MATCH 32u /* subject/issuer matches a "tls issuer-name" advisory */

typedef struct {
    char (*hash)[65]; /* lowercase hex SHA-256 of the SPKI */
    size_t n;
    size_t cap;
} spki_blocklist;

typedef struct {
    char subject[256];
    char issuer[256];
    char key_alg[16];
    int key_bits;
    char not_before[40];
    char not_after[40];
    long days_left; /* negative when expired */
    char spki_sha256[65];
    char ocsp_url[200]; /* first OCSP responder URL in the certificate, if any */
    char crl_url[200];  /* first CRL distribution point URL, if any */
    char matched[64];   /* which advisory string matched (TLSF_ISSUER_MATCH) */
    unsigned flags;
} tls_cert_info;

typedef struct {
    char host[128];
    unsigned short port;
    int connected;
    char error[160];
    char protocol[16];
    char cipher[64];
    long verify_code; /* X509_V_OK == 0 */
    char verify_text[128];
    char interception[64]; /* non-empty if the chain looks re-signed by a local TLS inspector */
    int ocsp_stapled;
    char ocsp_status[80];
    tls_cert_info certs[TLS_MAX_CERTS];
    int ncerts;
} tls_result;

/* Load SPKI hashes: one per line, 64 hex chars or 44-char base64, optional label after
   whitespace, '#' comments. 0 ok (even for an empty file), -1 cannot open / out of memory. */
int spki_blocklist_load(const char *path, spki_blocklist *bl);
int spki_blocklist_has(const spki_blocklist *bl, const char *hex);
void spki_blocklist_free(spki_blocklist *bl);

/* Names of common local TLS-inspection issuers; returns the matched name or NULL. */
const char *tls_detect_interception(const char *issuer_or_subject);

/* Permissive client context for auditing (any protocol/cipher the server offers). Peer
   verification results are recorded but never abort the handshake. ca_file may be NULL. */
SSL_CTX *tls_new_client_ctx(const char *ca_file);
SSL *tls_handshake(SSL_CTX *ctx, net_sock s, const char *host, int want_ocsp, char *err,
                   size_t errlen);

/* Connect, handshake and describe the presented chain. adv and bl may be NULL.
   0 = chain captured, -1 = could not connect/handshake (see out->error). */
int tls_audit_host(const char *host, unsigned short port, int timeout_ms, const char *ca_file,
                   const adv_list *adv, const spki_blocklist *bl, tls_result *out);

/* 1 for SSLv3, TLSv1.0 and TLSv1.1 (as named by SSL_get_version). */
int tls_protocol_is_weak(const char *protocol);

void tls_result_print(const tls_result *r, FILE *out);

#endif
