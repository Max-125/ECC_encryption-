#ifndef HEADER_H
#define HEADER_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>

EVP_PKEY* generate_EC_Key();
bool save_EC_Key(EVP_PKEY* pkey, const char* filename);
EVP_PKEY* load_Key(const char* filename);
bool derive_shared_secret(EVP_PKEY* local_key, EVP_PKEY* peer_key, std::string& secret);
bool AES_encrypt(const std::string& plaintext, const std::string& key, std::string& ciphertext);
bool AES_decrypt(const std::string& ciphertext, const std::string& key, std::string& plaintext);

#endif // HEADER_H
