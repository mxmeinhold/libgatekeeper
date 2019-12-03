#include "gatekeeper/gatekeeper.h"
#include "crypto.h"
#include "encoding.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#define GK_INITIAL_APPLICATION_SETTINGS 0x9
#define GK_FINAL_APPLICATION_SETTINGS 0xE0
#define GK_INITIAL_PICC_SETTINGS 0x09
#define GK_FINAL_PICC_SETTINGS 0x08
#define GK_INITIAL_FILE_SETTINGS 0x0000
#define GK_ASSOCIATION_FILE_SETTINGS 0x1FFF
#define GK_SIGNATURE_FILE_SETTINGS 0x2F33

#define GK_MASTER_AID 0x0
#define GK_BASE_AID 0xff77f0

#define GK_ASSOCIATION_LENGTH 37
#define GK_READ_PADDING (2*16 + 1)

#define GK_DES_KEY_LENGTH 8
#define GK_AES_KEY_LENGTH 16

static unsigned char GK_DEFAULT_DES_KEY[GK_DES_KEY_LENGTH] = { 0x0 };
static unsigned char GK_DEFAULT_AES_KEY[GK_AES_KEY_LENGTH] = { 0x0 };

typedef struct tag_app {
    unsigned char *master_key;
    unsigned char *read_key;
    unsigned char *auth_key;
    unsigned char *update_key;
} tag_app_t;

tag_app_t *tag_app_create() {
    tag_app_t *app = malloc(sizeof(tag_app_t));
    app->master_key = malloc(GK_AES_KEY_LENGTH);
    app->read_key = malloc(GK_AES_KEY_LENGTH);
    app->auth_key = malloc(GK_AES_KEY_LENGTH);
    app->update_key = malloc(GK_AES_KEY_LENGTH);
    return app;
}

void tag_app_free(tag_app_t *app) {
    free(app->master_key);
    free(app->read_key);
    free(app->auth_key);
    free(app->update_key);
    free(app);
}

typedef struct tag_data {
    char *uid;
    unsigned char *picc_master_key;
    size_t num_apps;
    tag_app_t **apps;
} tag_data_t;

tag_data_t *tag_data_create(char *uid, size_t num_apps) {
    tag_data_t *td = malloc(sizeof(tag_data_t));

    td->uid = malloc(strlen(uid) + 1);
    strncpy(td->uid, uid, strlen(uid) + 1);

    td->picc_master_key = NULL;
    td->num_apps = num_apps;
    td->apps = malloc(num_apps * sizeof(tag_data_t *));

    for (size_t slot = 0; slot < num_apps; slot++) {
        td->apps[slot] = tag_app_create();
    }

    return td;
}

void tag_data_free(tag_data_t *td) {
    free(td->uid);
    if (td->picc_master_key != NULL) free(td->picc_master_key);

    for (size_t slot = 0; slot < td->num_apps; slot++) {
        tag_app_free(td->apps[slot]);
    }

    free(td->apps);
    free(td);
}

realm_keys_t *realm_keys_create(char *auth_key, char *read_key, char *update_key, char *public_key, char *private_key) {
    realm_keys_t *realm_keys = malloc(sizeof(realm_keys_t));

    // Copy realm keys
    realm_keys->auth = malloc(strlen(auth_key) + 1);
    strncpy(realm_keys->auth, auth_key, strlen(auth_key) + 1);

    realm_keys->read = malloc(strlen(read_key) + 1);
    strncpy(realm_keys->read, read_key, strlen(read_key) + 1);

    realm_keys->update = malloc(strlen(update_key) + 1);
    strncpy(realm_keys->update, update_key, strlen(update_key) + 1);

    // Decode public/private keys
    realm_keys->public = gk_decode_public_key(public_key);
    if (realm_keys->public == NULL) {
        warnx("realm_keys_create: failed to decode public key");
        goto abort;
    }

    realm_keys->private = gk_decode_private_key(private_key);
    if (realm_keys->public == NULL) {
        warnx("realm_keys_create: failed to decode private key");
        goto abort_pk;
    }

    return realm_keys;

    abort_pk:
    EVP_PKEY_free(realm_keys->public);

    abort:
    free(realm_keys->auth);
    free(realm_keys->read);
    free(realm_keys->update);
    free(realm_keys);

    return NULL;
}

void realm_keys_free(realm_keys_t *realm_keys) {
    free(realm_keys->auth);
    free(realm_keys->read);
    free(realm_keys->update);
    EVP_PKEY_free(realm_keys->public);
    EVP_PKEY_free(realm_keys->private);
    free(realm_keys);
}

realm_t *realm_create(uint8_t slot, char *name, char *association_id, char *auth_key, char *read_key, char *update_key, char *public_key, char *private_key) {
    realm_t *realm = malloc(sizeof(realm_t));

    realm->slot = slot;
    realm->name = malloc(strlen(name) + 1);
    strncpy(realm->name, name, strlen(name) + 1);

    // Parse realm association ID
    realm->association_id = malloc(GK_ASSOCIATION_LENGTH);
    strncpy(realm->association_id, association_id, GK_ASSOCIATION_LENGTH);

    // Parse application keys
    realm->keys = realm_keys_create(auth_key, read_key, update_key, public_key, private_key);
    if (realm->keys == NULL) {
        warnx("realm_create: failed to parse realm keys");
        goto abort;
    }

    return realm;

    abort:
    free(realm->name);
    free(realm->association_id);
    free(realm);

    return NULL;
}

void realm_free(realm_t *realm) {
    free(realm->name);
    free(realm->association_id);
    realm_keys_free(realm->keys);
    free(realm);
}

void print_key(char *label, unsigned char *key, int key_len) {
    char *key_str = gk_bin_to_hex(key, key_len);
    warnx("%s: %s", label, key_str);
    free(key_str);
}

int issue_tag(MifareTag tag, char *system_secret, realm_t **realms, size_t num_realms) {
    int r;
    int retval = EXIT_FAILURE;

    MifareDESFireKey default_desfire_des_key = mifare_desfire_des_key_new(GK_DEFAULT_DES_KEY);
    MifareDESFireKey default_desfire_aes_key = mifare_desfire_aes_key_new(GK_DEFAULT_AES_KEY);

    r = mifare_desfire_connect(tag);
    if (r < 0) {
        // Failed to connect to tag
        return 4;
    }

    struct mifare_desfire_version_info version_info;
    r = mifare_desfire_get_version(tag, &version_info);
    if (r < 0) {
        // Failed to retrieve tag version information
        goto abort;
    }

    uint8_t zero_uid[7] = {0};
    if (memcmp(version_info.uid, zero_uid, sizeof(zero_uid)) == 0) {
        // Unsupported tag: random UID is already enabled
        goto abort;
    }

    char *tag_uid = freefare_get_tag_uid(tag);
    tag_data_t *td = tag_data_create(tag_uid, num_realms);
    free(tag_uid);

    warnx("Tag UID: %s", td->uid);

    for (size_t realm = 0; realm < num_realms; realm++) {
        int slot = realms[realm]->slot;
        int app_id = GK_BASE_AID + slot;
        MifareDESFireAID aid = mifare_desfire_aid_new(app_id);

        warnx("=== Create App %d ===", slot);
        warnx("Association ID: %s", realms[slot]->association_id);

        // Derive application master key
        r = gk_kdf(system_secret, app_id, 0, td->uid, GK_AES_KEY_LENGTH, &td->apps[slot]->master_key);
        if (r != GK_AES_KEY_LENGTH) {
            // Failed to derive application master key
            goto abort;
        }

        // Derive application read key
        r = gk_kdf(realms[slot]->keys->read, app_id, 1, NULL, GK_AES_KEY_LENGTH, &td->apps[slot]->read_key);
        if (r != GK_AES_KEY_LENGTH) {
            // Failed to derive slot read key
            goto abort;
        }

        // Derive application auth key
        r = gk_kdf(realms[slot]->keys->auth, app_id, 2, realms[slot]->association_id, GK_AES_KEY_LENGTH, &td->apps[slot]->auth_key);
        if (r != GK_AES_KEY_LENGTH) {
            // Failed to derive slot auth key
            goto abort;
        }

        // Derive application update key
        r = gk_kdf(realms[slot]->keys->update, app_id, 3, realms[slot]->association_id, GK_AES_KEY_LENGTH, &td->apps[slot]->update_key);
        if (r != GK_AES_KEY_LENGTH) {
            // Failed to derive slot update key
            goto abort;
        }

        print_key("App Master Key", td->apps[slot]->master_key, GK_AES_KEY_LENGTH);
        print_key("App Read Key", td->apps[slot]->read_key, GK_AES_KEY_LENGTH);
        print_key("App Auth Key", td->apps[slot]->auth_key, GK_AES_KEY_LENGTH);
        print_key("App Update Key", td->apps[slot]->update_key, GK_AES_KEY_LENGTH);

        // Sign association ID
        unsigned char *sig = NULL;
        size_t sig_length;
        if (gk_sign(realms[slot]->association_id, realms[slot]->keys->private, &sig, &sig_length) != 0) {
            warnx("issue_tag: failed to sign association ID for slot %d", slot);
            goto abort;
        }

        // Verify signature
        if (!gk_verify(realms[slot]->association_id, realms[slot]->keys->public, sig, sig_length)) {
            warnx("issue_tag: failed to verify signature for slot %d", slot);
            goto abort_sig;
        }

        // Create DESFire keys
        MifareDESFireKey master_key = mifare_desfire_aes_key_new(td->apps[slot]->master_key);
        MifareDESFireKey read_key = mifare_desfire_aes_key_new(td->apps[slot]->read_key);
        MifareDESFireKey auth_key = mifare_desfire_aes_key_new(td->apps[slot]->auth_key);
        MifareDESFireKey update_key = mifare_desfire_aes_key_new(td->apps[slot]->update_key);

        if (master_key == NULL || read_key == NULL || auth_key == NULL || update_key == NULL) {
            warnx("issue_tag: failed to create DESFire keys");
            goto abort_keys;
        }

        // Select master application
        r = mifare_desfire_select_application(tag, NULL);
        if (r < 0) {
            warnx("issue_tag: failed to select master application");
            goto abort_keys;
        }

        // Authenticate to tag
        r = mifare_desfire_authenticate(tag, GK_MASTER_AID, default_desfire_des_key);
        if (r < 0) {
            warnx("issue_tag: failed to authenticate to tag");
            goto abort_keys;
        }

        // Create application
        r = mifare_desfire_create_application_aes(tag, aid, GK_INITIAL_APPLICATION_SETTINGS, 4);
        if (r < 0) {
            warnx("issue_tag: failed to create application");
            goto abort_keys;
        }

        // Select application
        r = mifare_desfire_select_application(tag, aid);
        if (r < 0) {
            warnx("issue_tag: failed to select application");
            goto abort_keys;
        }

        // Authenticate to application
        r = mifare_desfire_authenticate(tag, 0, default_desfire_aes_key);
        if (r < 0) {
            warnx("issue_tag: failed to authenticate to application");
            goto abort_keys;
        }
        
        // Change application transport keys
        r = mifare_desfire_change_key(tag, 1, read_key, default_desfire_aes_key);
        if (r < 0) {
            warnx("issue_tag: failed to change application read key");
            goto abort_keys;
        }

        r = mifare_desfire_change_key(tag, 2, auth_key, default_desfire_aes_key);
        if (r < 0) {
            warnx("issue_tag: failed to change application auth key");
            goto abort_keys;
        }

        r = mifare_desfire_change_key(tag, 3, update_key, default_desfire_aes_key);
        if (r < 0) {
            warnx("issue_tag: failed to change application update key");
            goto abort_keys;
        }

        // Write association data file
        r = mifare_desfire_create_std_data_file(tag, 1, MDCM_ENCIPHERED, GK_INITIAL_FILE_SETTINGS, GK_ASSOCIATION_LENGTH);
        if (r < 0) {
            warnx("issue_tag: failed to create association data file");
            goto abort_keys;
        }

        r = mifare_desfire_write_data_ex(tag, 1, 0, GK_ASSOCIATION_LENGTH, realms[realm]->association_id, MDCM_ENCIPHERED);
        if (r < 0) {
            warnx("issue_tag: failed to write association");
            goto abort_keys;
        }

        // Create signature data file
        r = mifare_desfire_create_std_data_file(tag, 2, MDCM_ENCIPHERED, GK_INITIAL_FILE_SETTINGS, 4 + sig_length);
        if (r < 0) {
            warnx("issue_tag: failed to create signature data file");
            goto abort_keys;
        }

        unsigned char sig_len_bytes[4];
        sig_len_bytes[0] = (sig_length >> 24u);
        sig_len_bytes[1] = (sig_length >> 16u);
        sig_len_bytes[2] = (sig_length >> 8u);
        sig_len_bytes[3] = sig_length;

        r = mifare_desfire_write_data_ex(tag, 2, 0, 4, sig_len_bytes, MDCM_ENCIPHERED);
        if (r < 0) {
            warnx("issue_tag: failed to write signature length");
            goto abort_keys;
        }

        r = mifare_desfire_write_data_ex(tag, 2, 4, sig_length, sig, MDCM_ENCIPHERED);
        if (r < 0) {
            warnx("issue_tag: failed to write signature");
            goto abort_keys;
        }

        // Apply final file settings
        r = mifare_desfire_change_file_settings(tag, 1, MDCM_ENCIPHERED, GK_ASSOCIATION_FILE_SETTINGS);
        if (r < 0) {
            warnx("issue_tag: failed to change association file settings");
            goto abort_keys;
        }

        r = mifare_desfire_change_file_settings(tag, 2, MDCM_ENCIPHERED, GK_SIGNATURE_FILE_SETTINGS);
        if (r < 0) {
            warnx("issue_tag: failed to change signature file settings");
            goto abort_keys;
        }

        // Change application master key
        r = mifare_desfire_change_key(tag, 0, master_key, default_desfire_des_key);
        if (r < 0) {
            warnx("issue_tag: failed to change application master key");
            goto abort_keys;
        }

        // Re-authenticate to application
        r = mifare_desfire_authenticate(tag, 0, master_key);
        if (r < 0) {
            warnx("issue_tag: failed to re-authenticate to application");
            goto abort_keys;
        }

        // Apply final key settings
        r = mifare_desfire_change_key_settings(tag, GK_FINAL_APPLICATION_SETTINGS);
        if (r < 0) {
            warnx("issue_tag: failed to change application settings");
            goto abort_keys;
        }

        abort_keys:
        if (master_key != NULL) mifare_desfire_key_free(master_key);
        if (read_key != NULL) mifare_desfire_key_free(read_key);
        if (auth_key != NULL) mifare_desfire_key_free(auth_key);
        if (update_key != NULL) mifare_desfire_key_free(update_key);

        abort_sig:
        OPENSSL_free(sig);
    }

    warnx("=== Tag Configuration ===");

    // Derive PICC master key
    r = gk_kdf(system_secret, GK_MASTER_AID, 0, td->uid, GK_AES_KEY_LENGTH, &td->picc_master_key);
    if (r < 0) {
        // Failed to derive PICC master key
        goto abort;
    }

    MifareDESFireKey picc_master_key = mifare_desfire_aes_key_new(td->picc_master_key);
    print_key("PICC Master Key", td->picc_master_key, r);

    // Switch back to master application
    r = mifare_desfire_select_application(tag, NULL);
    if (r < 0) {
        warnx("issue_tag: failed to select master application");
        goto abort;
    }

    // Authenticate to tag
    r = mifare_desfire_authenticate(tag, 0, default_desfire_des_key);
    if (r < 0) {
        warnx("issue_tag: failed to authenticate to tag");
        goto abort;
    }

    // Change key settings to allow us to change the PICC master key
    r = mifare_desfire_change_key_settings(tag, GK_INITIAL_PICC_SETTINGS);
    if (r < 0) {
        warnx("issue_tag: failed to change tag key settings");
        goto abort;
    }

    // TODO: Must save real tag UID or we won't be able to re-derive PICC master key

//    // Change PICC master key
//    r = mifare_desfire_change_key(tag, 0, picc_master_key, default_desfire_key);
//    if (r < 0) {
//        warnx("issue_tag: failed to change PICC master key");
//        goto abort;
//    }
//
//    // Re-authenticate to target
//    r = mifare_desfire_authenticate(tag, 0, picc_master_key);
//    if (r < 0) {
//        warnx("issue_tag: failed to re-authenticate to tag");
//        goto abort;
//    }
//
//    // Apply the final key settings
//    r = mifare_desfire_change_key_settings(tag, GK_FINAL_PICC_SETTINGS);
//    if (r < 0) {
//        warnx("issue_tag: failed to change tag key settings");
//        goto abort;
//    }
//
//    // Enable random UID
//    r = mifare_desfire_set_configuration(tag, false, true);
//    if (r < 0) {
//        warnx("issue_tag: failed to update tag configuration");
//        goto abort;
//    }

    retval = 0;

    abort:
    if (picc_master_key != NULL) mifare_desfire_key_free(picc_master_key);
    mifare_desfire_key_free(default_desfire_des_key);
    mifare_desfire_key_free(default_desfire_aes_key);
    mifare_desfire_disconnect(tag);
    tag_data_free(td);

    return retval;
}

size_t authenticate_tag(MifareTag tag, realm_t *realm) {
    int r, retval = 0;
    int app_id = GK_BASE_AID + realm->slot;
    MifareDESFireAID aid = mifare_desfire_aid_new(app_id);

    unsigned char *read_key = malloc(GK_AES_KEY_LENGTH);
    unsigned char *auth_key = malloc(GK_AES_KEY_LENGTH);
    MifareDESFireKey desfire_read_key = NULL;
    MifareDESFireKey desfire_auth_key = NULL;

    /*
     * As of 2013-02-02 mifare_desfire_read_ex() with cipher/mac has a bug in that it will
     * need a buffer that is large enough to hold both the payload data and mac/padding. So we'll
     * allocate a larger buffer here and use explicit lengths.
     */
    char association_buf[GK_ASSOCIATION_LENGTH + GK_READ_PADDING];
    unsigned char signature_buf [EVP_PKEY_size(realm->keys->public) + GK_READ_PADDING];
    char association_id[GK_ASSOCIATION_LENGTH];
    unsigned char *signature = NULL; // Allocate this dynamically after reading length

    warnx("=== Authenticate Tag ===");

    // Derive application read key
    r = gk_kdf(realm->keys->read, app_id, 1, NULL, GK_AES_KEY_LENGTH, &read_key);
    if (r != GK_AES_KEY_LENGTH) {
        // Failed to derive read key
        goto abort;
    }

    print_key("App Read Key", read_key, GK_AES_KEY_LENGTH);
    desfire_read_key = mifare_desfire_aes_key_new(read_key);

    // Connect to tag
    r = mifare_desfire_connect(tag);
    if (r < 0) {
        warnx("authenticate_tag: Failed to connect to tag");
        goto abort;
    }

    // Select application
    r = mifare_desfire_select_application(tag, aid);
    if (r < 0) {
        warnx("authenticate_tag: failed to select application");
        goto abort_disconnect;
    }

    // Authenticate to application
    r = mifare_desfire_authenticate(tag, 1, desfire_read_key);
    if (r < 0) {
        warnx("authenticate_tag: failed to authenticate to application (read)");
        goto abort_disconnect;
    }

    // Read the association ID from the application
    r = mifare_desfire_read_data_ex(tag, 1, 0, GK_ASSOCIATION_LENGTH, &association_buf, MDCM_ENCIPHERED);
    if (r != GK_ASSOCIATION_LENGTH) {
        warnx("authenticate_tag: failed to read association ID");
        goto abort_disconnect;
    }

    memcpy(association_id, association_buf, GK_ASSOCIATION_LENGTH);
    warnx("Association ID: %s", association_id);

    // Derive authentication key
    r = gk_kdf(realm->keys->auth, app_id, 2, association_id, GK_AES_KEY_LENGTH, &auth_key);
    if (r != GK_AES_KEY_LENGTH) {
        // Failed to derive read key
        goto abort_disconnect;
    }

    print_key("App Auth Key", auth_key, GK_AES_KEY_LENGTH);
    desfire_auth_key = mifare_desfire_aes_key_new(auth_key);

    // Authenticate to application
    r = mifare_desfire_authenticate(tag, 2, desfire_auth_key);
    if (r < 0) {
        warnx("authenticate_tag: failed to authenticate to application (auth)");
        goto abort_disconnect;
    }

    // Read the signature from the application
    r = mifare_desfire_read_data_ex(tag, 2, 0, 4, &signature_buf, MDCM_ENCIPHERED);
    if (r < 0) {
        warnx("authenticate_tag: failed to read signature length");
        goto abort_disconnect;
    }

    size_t sig_length = (signature_buf[0] << 24u) + (signature_buf[1] << 16u) + (signature_buf[2] << 8u) + signature_buf[3];

    r = mifare_desfire_read_data_ex(tag, 2, 4, sig_length, &signature_buf, MDCM_ENCIPHERED);
    if (r < 0) {
        warnx("authenticate_tag: failed to read signature");
        goto abort_disconnect;
    }

    signature = malloc(sig_length);
    memcpy(signature, signature_buf, sig_length);

    // Verify signature
    if (!gk_verify(association_id, realm->keys->public, signature, sig_length)) {
        // Failed signature verification
        warnx("authenticate_tag: failed to verify signature");
        goto abort_disconnect;
    }

    // Successfully authenticated tag
    // TODO: Return association ID
    retval = 1;

    abort_disconnect:
    mifare_desfire_disconnect(tag);

    abort:
//    free(read_key);
//    free(auth_key);
//    free(association_buf);
//    free(signature_buf);
//    free(association_id);
//    if (signature != NULL) free(signature);
//    if (desfire_read_key != NULL) mifare_desfire_key_free(desfire_read_key);
//    if (desfire_auth_key != NULL) mifare_desfire_key_free(desfire_auth_key);

    return retval;
}