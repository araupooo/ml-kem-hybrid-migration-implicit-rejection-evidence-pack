/* implicit_reject.c — exercise ML-KEM implicit rejection (FIPS 203 §6,
 * Algorithm 18, Decaps_internal) across ML-KEM-512/768/1024.
 *
 * For each parameter set and each case:
 *   control        : valid encaps -> decaps; shared secrets must match.
 *   flip_first_bit : ciphertext with 1 bit flipped at ct[0].
 *   flip_mid_bit   : ciphertext with 1 bit flipped at ct[len/2].
 *   flip_last_bit  : ciphertext with 1 bit flipped at ct[len-1].
 *   flip_byte      : one whole byte of ct XORed with 0xFF at ct[0].
 *   all_zero_ct    : ciphertext of all zero bytes.
 *   random_ct      : fresh uniformly random ciphertext bytes.
 *   wrong_sk       : valid ciphertext decapsulated with a DIFFERENT keypair's
 *                    decapsulation key.
 *                    takes no ciphertext length — OQS_KEM_decaps(kem, ss, ct,
 *                    sk) reads exactly kem->length_ciphertext bytes — so the
 *                    FIPS 203 Section 7.3 ciphertext-length check is the
 *                    CALLER's responsibility, not the library's. A caller
 *                    that forwards a short buffer without checking it
 *                    violates the API contract. This is documented as an
 *                    API-contract observation (finding F-05), not tested at
 *                    runtime, because passing a short buffer to decaps would
 *                    be an out-of-bounds read. The length check is enforced
 *                    one layer up: RFC 10024 Section 4.2 requires the TLS
 *                    client to check the ciphertext length and abort with
 *                    illegal_parameter if it fails.
 *
 * Implicit rejection means: for a well-formed-length but invalid ciphertext,
 * decapsulation MUST still return OQS_SUCCESS and yield a pseudorandom
 * shared secret K' = J(z || c) (z is the 32-byte implicit-rejection value
 * inside the decapsulation key) instead of the sender's secret. The secret
 * is deterministic for a fixed (dk, ct) pair, is not equal to the sender's
 * secret, and the API gives no signal that rejection happened. Per FIPS 203
 * §3.3 the implicit-rejection flag is secret and must be destroyed before
 * Decaps_internal terminates; this harness therefore reports only
 * observable behaviour (return code, secret equality, determinism).
 *
 * CSV output: one row per trial:
 *   CSV: <scheme> <case> trial=<i> rc=<OQS_SUCCESS|OQS_ERROR>
 *        ss_eq_valid=<0|1> ss_deterministic=<0|1> ss_first8=<hex>
 * (ss_first8 is the first 8 hex chars of the decapsulated secret; all keys
 * are throwaway test keys generated inside this program.)
 * Summary lines: "SUMMARY: <scheme> <case> n=<n> rc_success=<n>
 * ss_eq_valid=<n> deterministic=<n>".
 * Exit code: 0 only if the control passes (secrets equal) and every tamper
 * case shows rc_success on well-formed lengths, zero ss_eq_valid, and full
 * determinism.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>

static void hex8(const uint8_t *b, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[2 * i] = h[b[i] >> 4];
        out[2 * i + 1] = h[b[i] & 0xf];
    }
    out[8] = '\0';
}

static int failures = 0;

static void run_case(OQS_KEM *kem, const char *scheme, const char *casename,
                     const uint8_t *pk, const uint8_t *sk, const uint8_t *ct,
                     const uint8_t *ss_valid, int n,
                     int expect_rc_success, int expect_eq_valid) {
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);
    int rc_success = 0, eq_valid = 0, deterministic = 0;
    char h[9];
    for (int i = 0; i < n; i++) {
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, sk);
        int ok = (rc == OQS_SUCCESS);
        int eq = (ok && memcmp(ss, ss_valid, kem->length_shared_secret) == 0);
        int det = 0;
        if (ok) {
            /* same (dk, ct) twice must give the same implicit-rejection secret */
            OQS_KEM_decaps(kem, ss2, ct, sk);
            det = (memcmp(ss, ss2, kem->length_shared_secret) == 0);
        }
        if (ok) rc_success++;
        if (eq) eq_valid++;
        if (det) deterministic++;
        hex8(ss, h);
        printf("CSV: %s %s trial=%d rc=%s ss_eq_valid=%d ss_deterministic=%d ss_first8=%s\n",
               scheme, casename, i, ok ? "OQS_SUCCESS" : "OQS_ERROR", eq, det, h);
    }
    printf("SUMMARY: %s %s n=%d rc_success=%d ss_eq_valid=%d deterministic=%d\n",
           scheme, casename, n, rc_success, eq_valid, deterministic);
    if (expect_rc_success) {
        if (rc_success != n) { printf("FAIL: %s %s rc_success != n\n", scheme, casename); failures++; }
        if (deterministic != n) { printf("FAIL: %s %s implicit-rejection secret not deterministic\n", scheme, casename); failures++; }
    }
    if (expect_eq_valid) {
        /* control: the decapsulated secret MUST equal the valid secret */
        if (eq_valid != n) { printf("FAIL: %s %s control secret did not match\n", scheme, casename); failures++; }
    } else {
        /* tamper: the decapsulated secret must NEVER equal the valid secret */
        if (eq_valid != 0)   { printf("FAIL: %s %s tampered ciphertext accepted as valid\n", scheme, casename); failures++; }
    }
    free(ss); free(ss2);
}

static void run_scheme(const char *scheme, int n) {
    OQS_KEM *kem = OQS_KEM_new(scheme);
    if (kem == NULL) {
        printf("ERROR: OQS_KEM_new(%s) failed\n", scheme);
        failures++;
        return;
    }
    printf("SCHEME: %s ek=%zu dk=%zu ct=%zu ss=%zu\n", scheme,
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *pk2 = malloc(kem->length_public_key);
    uint8_t *sk2 = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ctm = malloc(kem->length_ciphertext);
    uint8_t *ss_valid = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);

    /* fresh keypair per trial set, so wrong_sk uses a genuinely different dk */
    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_keypair(kem, pk2, sk2);
    if (OQS_KEM_encaps(kem, ct, ss_valid, pk) != OQS_SUCCESS) {
        printf("ERROR: %s encaps failed\n", scheme);
        failures++;
        goto done;
    }
    if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS ||
        memcmp(ss_valid, ss_d, kem->length_shared_secret) != 0) {
        printf("FAIL: %s control decaps did not reproduce the encaps secret\n", scheme);
        failures++;
        goto done;
    }
    run_case(kem, scheme, "control", pk, sk, ct, ss_valid, n, 1, 1);

    /* flip one bit at three positions */
    memcpy(ctm, ct, kem->length_ciphertext);
    ctm[0] ^= 0x01;
    run_case(kem, scheme, "flip_first_bit", pk, sk, ctm, ss_valid, n, 1, 0);
    memcpy(ctm, ct, kem->length_ciphertext);
    ctm[kem->length_ciphertext / 2] ^= 0x01;
    run_case(kem, scheme, "flip_mid_bit", pk, sk, ctm, ss_valid, n, 1, 0);
    memcpy(ctm, ct, kem->length_ciphertext);
    ctm[kem->length_ciphertext - 1] ^= 0x01;
    run_case(kem, scheme, "flip_last_bit", pk, sk, ctm, ss_valid, n, 1, 0);

    /* flip a whole byte */
    memcpy(ctm, ct, kem->length_ciphertext);
    ctm[0] ^= 0xFF;
    run_case(kem, scheme, "flip_byte", pk, sk, ctm, ss_valid, n, 1, 0);

    /* all-zero ciphertext */
    memset(ctm, 0, kem->length_ciphertext);
    run_case(kem, scheme, "all_zero_ct", pk, sk, ctm, ss_valid, n, 1, 0);

    /* random ciphertext (fresh random bytes each trial) */
    {
        uint8_t *ss = malloc(kem->length_shared_secret);
        uint8_t *ss2 = malloc(kem->length_shared_secret);
        int rc_success = 0, eq_valid = 0, deterministic = 0;
        char h[9];
        for (int i = 0; i < n; i++) {
            OQS_randombytes(ctm, kem->length_ciphertext);
            OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ctm, sk);
            int ok = (rc == OQS_SUCCESS);
            int eq = (ok && memcmp(ss, ss_valid, kem->length_shared_secret) == 0);
            int det = 0;
            if (ok) {
                OQS_KEM_decaps(kem, ss2, ctm, sk);
                det = (memcmp(ss, ss2, kem->length_shared_secret) == 0);
            }
            if (ok) rc_success++;
            if (eq) eq_valid++;
            if (det) deterministic++;
            hex8(ss, h);
            printf("CSV: %s random_ct trial=%d rc=%s ss_eq_valid=%d ss_deterministic=%d ss_first8=%s\n",
                   scheme, i, ok ? "OQS_SUCCESS" : "OQS_ERROR", eq, det, h);
        }
        printf("SUMMARY: %s random_ct n=%d rc_success=%d ss_eq_valid=%d deterministic=%d\n",
               scheme, n, rc_success, eq_valid, deterministic);
        if (rc_success != n || eq_valid != 0 || deterministic != n) {
            printf("FAIL: %s random_ct expectations violated\n", scheme);
            failures++;
        }
        free(ss); free(ss2);
    }

    /* wrong decapsulation key */
    run_case(kem, scheme, "wrong_sk", pk, sk2, ct, ss_valid, n, 1, 0);

    /* truncated ciphertext: input-length check must reject it */

done:
    free(pk); free(sk); free(pk2); free(sk2);
    free(ct); free(ctm); free(ss_valid); free(ss_d);
    OQS_KEM_free(kem);
}

int main(int argc, char **argv) {
    int n = 50;
    if (argc > 1) n = atoi(argv[1]);
    if (n <= 0) n = 50;
    printf("implicit_reject: n=%d per case liboqs=%s\n", n, OQS_VERSION_TEXT);
    run_scheme("ML-KEM-512", n);
    run_scheme("ML-KEM-768", n);
    run_scheme("ML-KEM-1024", n);
    printf("implicit_reject: failures=%d %s\n", failures,
           failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    return failures == 0 ? 0 : 1;
}
