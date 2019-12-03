#ifndef GATEKEEPER_H
#define GATEKEEPER_H

#include <nfc/nfc.h>
#include <freefare.h>
#include <openssl/pem.h>

typedef struct RealmKeys {
    char *auth;
    char *read;
    char *update;
    EVP_PKEY *public;
    EVP_PKEY *private;
} realm_keys_t;

typedef struct Realm {
    uint8_t slot;
    char *name;
    char *association_id;
    realm_keys_t *keys;
} realm_t;

realm_t *realm_create(uint8_t slot, char *name, char *associationId, char *auth_key, char *read_key, char *update_key,
        char *public_key, char *private_key);

void realm_free(realm_t *realm);

int issue_tag(MifareTag tag, char *system_secret, realm_t **realms, size_t num_realms);

size_t authenticate_tag(MifareTag tag, realm_t *realm);

#endif //GATEKEEPER_H
