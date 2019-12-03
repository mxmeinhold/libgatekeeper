#ifndef ENCODING_H
#define ENCODING_H

EVP_PKEY *gk_decode_public_key(char *public_key);

EVP_PKEY *gk_decode_private_key(char *private_key);

char *gk_base64_encode(const unsigned char *data, size_t data_length);

char *gk_bin_to_hex(const unsigned char *bin, size_t len);

size_t gk_hex_to_bin(const char *hex, unsigned char **bytes);

#endif //ENCODING_H
