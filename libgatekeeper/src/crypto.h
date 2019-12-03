#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdlib.h>
#include <openssl/crypto.h>
#include <uuid/uuid.h>

int gk_kdf(const char *secret, uint32_t app_id, uint8_t key_no, char *data, size_t key_length, unsigned char **derived_key);

int gk_sign(const char *data, EVP_PKEY *private_key, unsigned char **sig, size_t *sig_length);

size_t gk_verify(const char *data, EVP_PKEY *public_key, unsigned char *sig, size_t sig_length);

#endif //CRYPTO_H
