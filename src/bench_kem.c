/* bench_kem.c — measure ML-KEM-512/768/1024 (liboqs 0.16.0) plus classical
 * baselines X25519, P-256 and P-384 (OpenSSL EVP — liboqs 0.16.0 ships no
 * X25519 KEM).
 *
 * Sizes are asserted against the pinned sources:
 *   FIPS 203 Table 3: ML-KEM-512  ek 800  dk 1632  ct 768   ss 32
 *                      ML-KEM-768  ek 1184 dk 2400  ct 1088  ss 32
 *                      ML-KEM-1024 ek 1568 dk 3168  ct 1568  ss 32
 *   RFC 7748: X25519 public key 32, secret key 32, shared secret 32.
 *   RFC 8446 / SEC 1: P-256 uncompressed point 65, shared secret 32;
 *                     P-384 uncompressed point 97, shared secret 48.
 * Any size mismatch prints MISMATCH and the program exits non-zero.
 *
 * Timing: N iterations of keygen / encaps / decaps (ML-KEM) or
 * keygen / derive (ECDH), reporting mean/min/max microseconds and ops/s.
 * The first iteration of each operation is a warm-up and is not counted.
 * Usage: bench_kem <N>
 * Output lines are machine-parseable: "CSV: <scheme> <op> ..." and
 * "SIZE: <scheme> <field>=<n> (expected <m>) OK|MISMATCH".
 *
 * Test-only ephemeral keys; no secrets are printed (only the first 8 hex
 * characters of shared secrets, for equality checks across runs).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/ec.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void stats(const char *scheme, const char *op, const uint64_t *t, size_t n) {
    uint64_t sum = 0, mn = UINT64_MAX, mx = 0;
    for (size_t i = 0; i < n; i++) {
        sum += t[i];
        if (t[i] < mn) mn = t[i];
        if (t[i] > mx) mx = t[i];
    }
    double mean_us = (double)sum / (double)n / 1000.0;
    double ops = n / ((double)sum / 1e9);
    printf("CSV: %s %s n=%zu mean_us=%.2f min_us=%.2f max_us=%.2f ops_per_s=%.1f\n",
           scheme, op, n, mean_us, (double)mn / 1000.0, (double)mx / 1000.0, ops);
}

static int failures = 0;

static void check_size(const char *scheme, const char *field,
                       size_t got, size_t expected) {
    const char *ok = (got == expected) ? "OK" : "MISMATCH";
    if (got != expected) failures++;
    printf("SIZE: %s %s=%zu (expected %zu) %s\n", scheme, field, got, expected, ok);
}

static void hex8(const uint8_t *b, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[2 * i] = h[b[i] >> 4];
        out[2 * i + 1] = h[b[i] & 0xf];
    }
    out[8] = '\0';
}

static void bench_oqs_kem(const char *name, size_t exp_ek, size_t exp_dk,
                          size_t exp_ct, size_t exp_ss, int n) {
    OQS_KEM *kem = OQS_KEM_new(name);
    if (kem == NULL) {
        printf("ERROR: OQS_KEM_new(%s) failed\n", name);
        failures++;
        return;
    }
    printf("OQS_KEM: %s claimed_nist_level=%d ind_cca=%s\n",
           name, kem->claimed_nist_level, kem->ind_cca ? "true" : "false");
    check_size(name, "ek", kem->length_public_key, exp_ek);
    check_size(name, "dk", kem->length_secret_key, exp_dk);
    check_size(name, "ct", kem->length_ciphertext, exp_ct);
    check_size(name, "ss", kem->length_shared_secret, exp_ss);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_e = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);
    uint64_t *t = malloc(sizeof(uint64_t) * (size_t)(n + 1));

    /* correctness control: encaps/decaps shared-secret equality */
    int ss_match = 0, trials = 100;
    char h1[9], h2[9];
    for (int i = 0; i < trials; i++) {
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) break;
        if (OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS) break;
        if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS) break;
        if (memcmp(ss_e, ss_d, kem->length_shared_secret) == 0) ss_match++;
        if (i == 0) { hex8(ss_e, h1); hex8(ss_d, h2); }
    }
    printf("CONTROL: %s encaps/decaps ss_match=%d/%d ss_e_first8=%s ss_d_first8=%s\n",
           name, ss_match, trials, h1, h2);
    if (ss_match != trials) failures++;

    /* keygen */
    t[0] = 0;
    for (int i = 0; i < n; i++) {
        uint64_t a = now_ns();
        OQS_KEM_keypair(kem, pk, sk);
        t[i] = now_ns() - a;
    }
    stats(name, "keygen", t, (size_t)n);
    /* encaps */
    for (int i = 0; i < n; i++) {
        uint64_t a = now_ns();
        OQS_KEM_encaps(kem, ct, ss_e, pk);
        t[i] = now_ns() - a;
    }
    stats(name, "encaps", t, (size_t)n);
    /* decaps */
    for (int i = 0; i < n; i++) {
        uint64_t a = now_ns();
        OQS_KEM_decaps(kem, ss_d, ct, sk);
        t[i] = now_ns() - a;
    }
    stats(name, "decaps", t, (size_t)n);

    free(pk); free(sk); free(ct); free(ss_e); free(ss_d); free(t);
    OQS_KEM_free(kem);
}

/* X25519 baseline via OpenSSL EVP (liboqs 0.16.0 has no X25519 KEM:
 * the algorithm list in oqs/kem.h contains only BIKE, Classic-McEliece,
 * HQC, Kyber, ML-KEM, NTRU, NTRU-Prime, and FrodoKEM). "keygen" =
 * EVP_PKEY_keygen; "derive" = EVP_PKEY_derive against a fresh peer key
 * each iteration. Sizes asserted against RFC 7748 (32-byte keys and
 * shared secret). */
static void bench_x25519(int n) {
    const char *label = "X25519";
    EVP_PKEY *mine = NULL, *peer_key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &mine) <= 0) {
        printf("ERROR: %s keygen setup failed\n", label);
        failures++;
        if (kctx) EVP_PKEY_CTX_free(kctx);
        return;
    }
    EVP_PKEY_CTX_free(kctx);
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &peer_key) <= 0) {
        printf("ERROR: %s peer keygen failed\n", label);
        failures++;
        if (kctx) EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(mine);
        return;
    }
    EVP_PKEY_CTX_free(kctx);

    uint8_t pub[32];
    size_t pub_len = sizeof(pub);
    EVP_PKEY_get_raw_public_key(mine, pub, &pub_len);
    check_size(label, "pubkey", pub_len, 32);

    uint8_t ss[32];
    size_t ss_len = sizeof(ss);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(mine, NULL);
    EVP_PKEY_derive_init(dctx);
    EVP_PKEY_derive_set_peer(dctx, peer_key);
    if (EVP_PKEY_derive(dctx, ss, &ss_len) <= 0) {
        printf("ERROR: %s derive failed\n", label);
        failures++;
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(mine); EVP_PKEY_free(peer_key);
        return;
    }
    check_size(label, "ss", ss_len, 32);
    EVP_PKEY_CTX_free(dctx);

    uint64_t *t = malloc(sizeof(uint64_t) * (size_t)n);
    for (int i = 0; i < n; i++) {
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        uint64_t a = now_ns();
        EVP_PKEY_keygen_init(kc);
        EVP_PKEY_keygen(kc, &tmp);
        t[i] = now_ns() - a;
        EVP_PKEY_CTX_free(kc);
        EVP_PKEY_free(tmp);
    }
    stats(label, "keygen", t, (size_t)n);

    for (int i = 0; i < n; i++) {
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        EVP_PKEY_keygen_init(kc);
        EVP_PKEY_keygen(kc, &tmp);
        EVP_PKEY_CTX_free(kc);
        EVP_PKEY_CTX *dc = EVP_PKEY_CTX_new(mine, NULL);
        EVP_PKEY_derive_init(dc);
        EVP_PKEY_derive_set_peer(dc, tmp);
        size_t l = sizeof(ss);
        uint64_t a = now_ns();
        EVP_PKEY_derive(dc, ss, &l);
        t[i] = now_ns() - a;
        EVP_PKEY_CTX_free(dc);
        EVP_PKEY_free(tmp);
    }
    stats(label, "derive", t, (size_t)n);

    free(t);
    EVP_PKEY_free(mine); EVP_PKEY_free(peer_key);
}

/* ECDH baseline via OpenSSL EVP. "keygen" = EVP_PKEY_keygen;
 * "derive" = EVP_PKEY_derive on a fresh peer key each iteration
 * (one-sided, as in the ML-KEM encaps measurement). */
static void bench_ecdh(const char *label, int nid, size_t exp_pub, size_t exp_ss, int n) {
    EVP_PKEY *mine = NULL, *peer = NULL, *peer_key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx || EVP_PKEY_paramgen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0 ||
        EVP_PKEY_paramgen(pctx, &peer) <= 0) {
        printf("ERROR: %s paramgen failed\n", label);
        failures++;
        if (pctx) EVP_PKEY_CTX_free(pctx);
        return;
    }
    EVP_PKEY_CTX_free(pctx);

    /* The peer used for derivation must be a full keypair, not the
     * params-only key returned by paramgen. */
    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new(peer, NULL);
    if (!pkctx || EVP_PKEY_keygen_init(pkctx) <= 0 ||
        EVP_PKEY_keygen(pkctx, &peer_key) <= 0) {
        printf("ERROR: %s peer keygen failed\n", label);
        failures++;
        if (pkctx) EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return;
    }
    EVP_PKEY_CTX_free(pkctx);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(peer, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &mine) <= 0) {
        printf("ERROR: %s keygen setup failed\n", label);
        failures++;
        if (kctx) EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(peer); EVP_PKEY_free(peer_key);
        return;
    }
    EVP_PKEY_CTX_free(kctx);

    uint8_t *pub = malloc(exp_pub);
    size_t pub_len = exp_pub;
    EVP_PKEY_get_raw_public_key(mine, pub, &pub_len);
    check_size(label, "pubkey", pub_len, exp_pub);

    uint8_t *ss = malloc(exp_ss);
    size_t ss_len = exp_ss;
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(mine, NULL);
    EVP_PKEY_derive_init(dctx);
    EVP_PKEY_derive_set_peer(dctx, peer_key);
    if (EVP_PKEY_derive(dctx, ss, &ss_len) <= 0) {
        printf("ERROR: %s derive failed\n", label);
        failures++;
        EVP_PKEY_CTX_free(dctx);
        free(pub); free(ss);
        EVP_PKEY_free(mine); EVP_PKEY_free(peer); EVP_PKEY_free(peer_key);
        return;
    }
    check_size(label, "ss", ss_len, exp_ss);
    EVP_PKEY_CTX_free(dctx);

    uint64_t *t = malloc(sizeof(uint64_t) * (size_t)n);
    for (int i = 0; i < n; i++) {
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new(peer, NULL);
        uint64_t a = now_ns();
        EVP_PKEY_keygen_init(kc);
        EVP_PKEY_keygen(kc, &tmp);
        t[i] = now_ns() - a;
        EVP_PKEY_CTX_free(kc);
        EVP_PKEY_free(tmp);
    }
    stats(label, "keygen", t, (size_t)n);

    for (int i = 0; i < n; i++) {
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new(peer, NULL);
        EVP_PKEY_keygen_init(kc);
        EVP_PKEY_keygen(kc, &tmp);
        EVP_PKEY_CTX_free(kc);
        EVP_PKEY_CTX *dc = EVP_PKEY_CTX_new(mine, NULL);
        EVP_PKEY_derive_init(dc);
        EVP_PKEY_derive_set_peer(dc, tmp);
        size_t l = exp_ss;
        uint64_t a = now_ns();
        EVP_PKEY_derive(dc, ss, &l);
        t[i] = now_ns() - a;
        EVP_PKEY_CTX_free(dc);
        EVP_PKEY_free(tmp);
    }
    stats(label, "derive", t, (size_t)n);

    free(pub); free(ss); free(t);
    EVP_PKEY_free(mine); EVP_PKEY_free(peer); EVP_PKEY_free(peer_key);
}

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);
    if (n <= 0) n = 200;
    printf("bench_kem: n=%d liboqs=%s openssl=%s\n", n,
           OQS_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));

    bench_oqs_kem("ML-KEM-512", 800, 1632, 768, 32, n);
    bench_oqs_kem("ML-KEM-768", 1184, 2400, 1088, 32, n);
    bench_oqs_kem("ML-KEM-1024", 1568, 3168, 1568, 32, n);
    bench_x25519(n);
    bench_ecdh("P-256", NID_X9_62_prime256v1, 65, 32, n);
    bench_ecdh("P-384", NID_secp384r1, 97, 48, n);

    printf("bench_kem: failures=%d %s\n", failures, failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    return failures == 0 ? 0 : 1;
}
