#include <err.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define HEX_TABLE "0123456789abcdef"

const int UUID_PART_SIZES[] = { 8, 4, 4, 4, 12 };

EVP_PKEY *gk_decode_public_key(char *public_key) {
    BIO *bio = BIO_new_mem_buf(public_key, (int) strlen(public_key));
    EVP_PKEY *ec = PEM_read_bio_PUBKEY(bio, NULL, 0, NULL);
    BIO_free_all(bio);
    return ec;
}

EVP_PKEY *gk_decode_private_key(char *private_key) {
    BIO *bio = BIO_new_mem_buf(private_key, (int) strlen(private_key));
    EVP_PKEY *ec = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    BIO_free_all(bio);
    return ec;
}

char *gk_base64_encode(const unsigned char *data, size_t data_length) {
    int retval = -1;

    // Create BIO to perform base64
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Create BIO to hold the result
    BIO *mem = BIO_new(BIO_s_mem());

    // Chain BIOs, so writing to b64 will encode base64 and write to mem
    mem = BIO_push(b64, mem);

    // Encode
    BIO_write(b64, data, data_length);
    BIO_flush(b64);

    // Extract the underlying BUF_MEM struct
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    // Copy BIO data into a new buffer and return
    char *buf = malloc(bptr->length);
    memcpy(buf, bptr->data, bptr->length - 1);
    buf[bptr->length - 1] = 0;

    BIO_free_all(b64);
    return buf;
}

char *gk_bin_to_hex(const unsigned char *bin, size_t len) {
    if (bin == NULL || len == 0) {
        return NULL;
    }

    char *out = malloc((len * 2) + 1);
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = HEX_TABLE[bin[i] >> 4u];
        out[(i * 2) + 1] = HEX_TABLE[bin[i] & 0x0Fu];
    }

    out[len * 2] = '\0';
    return out;
}

uint8_t gk_nibble_from_char(const char c) {
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t) (c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t) (c - 'A' + 10);
    return 255;
}

size_t gk_hex_to_bin(const char *hex, unsigned char **bytes) {
    size_t len = strlen(hex);

    if (len % 2 != 0) {
        return 0;
    }

    len /= 2;
    *bytes = malloc(len);

    for (size_t i = 0; i < len; i++) {
        (*bytes)[i] = (unsigned) (gk_nibble_from_char(hex[i * 2]) << 4u) | gk_nibble_from_char(hex[(i * 2) + 1]);
    }

    return len;
}

int gk_mangle_uuid(const char *uuid, unsigned char *mangled_uuid) {
    size_t inpos = 0, outpos = 0;

    if (uuid == NULL) {
        warnx("gk_mangle_uuid: invalid arguments");
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < sizeof(UUID_PART_SIZES) / sizeof(UUID_PART_SIZES[0]); i++) {
        if (i != 0) {
            if (inpos >= 36) {
                return -1;
            }

            if (uuid[inpos++] != '-') {
                return -1;
            }
        }

        for (int j = 0; j < UUID_PART_SIZES[i]; j++) {
            if (outpos >= 32 || inpos >= 32) {
                return -1;
            }

            char in = uuid[inpos++];
            if ((in >= '0' && in <= '9') || (in >= 'a' && in <= 'f')) {
                mangled_uuid[outpos++] = (unsigned) in;
            } else {
                return -1;
            }
        }
    }

    return EXIT_SUCCESS;
}

int gk_unmangle_uuid(const char *mangled_uuid, size_t mangled_uuid_length, char *uuid, size_t uuid_length) {
    size_t inpos = 0, outpos = 0;

    if (uuid == NULL || uuid_length == 0 || mangled_uuid == NULL || mangled_uuid_length == 0) {
        return -1;
    }

    for (size_t i = 0; i < sizeof(UUID_PART_SIZES) / sizeof(UUID_PART_SIZES[0]); i++) {
        if (i != 0) {
            if (outpos >= uuid_length) {
                return -1;
            }
            uuid[outpos++] = '-';
        }

        for (int j = 0; j < UUID_PART_SIZES[i]; j++) {
            if (inpos >= mangled_uuid_length || outpos >= uuid_length) {
                return -1;
            }

            char in = mangled_uuid[inpos++];
            if ((in >= '0' && in <= '9') || (in >= 'a' && in <= 'f')) {
                uuid[outpos++] = in;
            } else {
                return -1;
            }
        }
    }

    return 0;
}