#define _CRT_SECURE_NO_WARNINGS
#include "ECC.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>

void print_openssl_error() {
    unsigned long errCode;
    while ((errCode = ERR_get_error())) {
        char* err = ERR_error_string(errCode, nullptr);
        std::cerr << "OpenSSL Error: " << err << std::endl;
    }
}

EVP_PKEY* generate_EC_Key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (!pctx) {
        std::cerr << "Error creating EVP_PKEY_CTX" << std::endl;
        print_openssl_error();
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "Error initializing keygen context" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Error setting curve" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "Error generating EC key" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

bool save_EC_Key(EVP_PKEY* pkey, const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        std::cerr << "Error opening file to write key" << std::endl;
        return false;
    }

    if (PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        std::cerr << "Error writing private key to file" << std::endl;
        fclose(fp);
        print_openssl_error();
        return false;
    }

    fclose(fp);
    return true;
}

EVP_PKEY* load_Key(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        std::cerr << "Error opening file to read key" << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    if (!pkey) {
        std::cerr << "Error reading private key from file" << std::endl;
        print_openssl_error();
    }
    fclose(fp);
    return pkey;
}

bool derive_shared_secret(EVP_PKEY* local_key, EVP_PKEY* peer_key, std::string& secret) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_key, nullptr);
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX" << std::endl;
        print_openssl_error();
        return false;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        std::cerr << "Error initializing key derivation" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        std::cerr << "Error setting peer key" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        std::cerr << "Error determining buffer length" << std::endl;
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    unsigned char* secret_buf = new unsigned char[secret_len];
    if (EVP_PKEY_derive(ctx, secret_buf, &secret_len) <= 0) {
        std::cerr << "Error deriving shared secret" << std::endl;
        print_openssl_error();
        delete[] secret_buf;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    secret.assign(reinterpret_cast<char*>(secret_buf), secret_len);
    delete[] secret_buf;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool AES_encrypt(const std::string& plaintext, const std::string& key, std::string& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP_CIPHER_CTX" << std::endl;
        print_openssl_error();
        return false;
    }

    const unsigned char* key_data = reinterpret_cast<const unsigned char*>(key.data());
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating random IV" << std::endl;
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_data, iv) != 1) {
        std::cerr << "Error initializing AES encryption" << std::endl;
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    unsigned char* out = new unsigned char[plaintext.size() + AES_BLOCK_SIZE];
    if (EVP_EncryptUpdate(ctx, out, &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        std::cerr << "Error during AES encryption" << std::endl;
        print_openssl_error();
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        std::cerr << "Error finalizing AES encryption" << std::endl;
        print_openssl_error();
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    ciphertext.assign(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    ciphertext.append(reinterpret_cast<char*>(out), ciphertext_len);

    delete[] out;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AES_decrypt(const std::string& ciphertext, const std::string& key, std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating EVP_CIPHER_CTX" << std::endl;
        print_openssl_error();
        return false;
    }

    const unsigned char* key_data = reinterpret_cast<const unsigned char*>(key.data());
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data());
    const unsigned char* encrypted_data = reinterpret_cast<const unsigned char*>(ciphertext.data() + AES_BLOCK_SIZE);
    int encrypted_data_len = ciphertext.size() - AES_BLOCK_SIZE;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_data, iv) != 1) {
        std::cerr << "Error initializing AES decryption" << std::endl;
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    unsigned char* out = new unsigned char[encrypted_data_len + AES_BLOCK_SIZE];
    if (EVP_DecryptUpdate(ctx, out, &len, encrypted_data, encrypted_data_len) != 1) {
        std::cerr << "Error during AES decryption" << std::endl;
        print_openssl_error();
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) {
        std::cerr << "Error finalizing AES decryption" << std::endl;
        print_openssl_error();
        delete[] out;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    plaintext.assign(reinterpret_cast<char*>(out), plaintext_len);

    delete[] out;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
