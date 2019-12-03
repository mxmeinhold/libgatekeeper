#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <mach/machine.h>

#define GK_PBKDF2_ITERATIONS 10000

int gk_kdf(const char *secret, uint32_t app_id, uint8_t key_no, char *data, uint32_t key_length, unsigned char **derived_key) {
    int retval = -1;

    if (secret == NULL || key_length < 1) {
        warnx("gk_kdf: invalid arguments");
        return retval;
    }

    // Construct salt
    if (data == NULL) data = "";
    size_t salt_len = snprintf(NULL, 0, "%d%d%s", app_id, key_no, data);
    char *salt = malloc(salt_len + 1);
    snprintf(salt, salt_len + 1, "%d%d%s", app_id, key_no, data);

    // Derive key
    *derived_key = malloc(key_length);
    if (!PKCS5_PBKDF2_HMAC(secret, -1, (unsigned char *) salt, salt_len, GK_PBKDF2_ITERATIONS, EVP_sha256(), key_length, *derived_key)) {
        warnx("gk_kdf: failed to derive key");
        free(derived_key);
        goto abort;
    }

    retval = key_length;

    abort:
    free(salt);

    return retval;
}

int gk_sign(const char *data, EVP_PKEY *private_key, unsigned char **sig, size_t *sig_length) {
    int retval = -1;

    if (data == NULL || private_key == NULL) {
        warnx("gk_sign: invalid arguments");
        return retval;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL) {
        warnx("gk_sign: failed to initialize");
        return retval;
    }

    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key)
            || !EVP_DigestSignUpdate(md_ctx, data, strlen(data))
            || !EVP_DigestSignFinal(md_ctx, NULL, sig_length)) {
        warnx("gk_sign: failed to sign");
        goto abort;
    }

    *sig = OPENSSL_malloc(*sig_length);

    if (!EVP_DigestSignFinal(md_ctx, *sig, sig_length)) {
        OPENSSL_free(sig);
        goto abort;
    }

    retval = 0;

    abort:
    EVP_MD_CTX_destroy(md_ctx);

    return retval;
}

size_t gk_verify(const char *data, EVP_PKEY *public_key, unsigned char *sig, size_t sig_length) {
    int retval = 0;

    if (data == NULL || public_key == NULL) {
        warnx("gk_verify: invalid arguments");
        return retval;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL) {
        warnx("gk_verify: failed to initialize");
        return retval;
    }

    if (!EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, public_key)
        || !EVP_DigestVerifyUpdate(md_ctx, data, strlen(data))
        || !EVP_DigestVerifyFinal(md_ctx, sig, sig_length)) {
        warnx("gk_verify: failed to verify");
        goto abort;
    }

    retval = 1;

    abort:
    EVP_MD_CTX_destroy(md_ctx);

    return retval;
}