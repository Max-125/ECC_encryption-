#define _CRT_SECURE_NO_WARNINGS
#include <openssl/applink.c>
#include "ECC.h"
#include <iostream>
#include <string>
#include <fstream>

int main() {
    std::string filename;
    std::cout << "Enter the file name: ";
    std::getline(std::cin >> std::ws, filename);

    std::string mode;
    std::cout << "Choose encryption or decryption (encrypt/decrypt): ";
    std::cin >> mode;

    bool encrypt = (mode == "encrypt");

    std::ifstream file_in(filename);
    if (!file_in) {
        std::cerr << "Error: Unable to open file." << std::endl;
        return 1;
    }

    std::string text((std::istreambuf_iterator<char>(file_in)), {});
    file_in.close();

    const char* privateKeyFile = "ec_key.pem";
    EVP_PKEY* pkey = generate_EC_Key();
    if (!pkey || !save_EC_Key(pkey, privateKeyFile)) {
        std::cerr << "Failed to generate or save EC key" << std::endl;
        return 1;
    }

    EVP_PKEY* loadedPkey = load_Key(privateKeyFile);
    if (!loadedPkey) {
        std::cerr << "Failed to load EC key" << std::endl;
        return 1;
    }

    EVP_PKEY* peerKey = generate_EC_Key();
    if (!peerKey) {
        std::cerr << "Failed to generate peer EC key" << std::endl;
        return 1;
    }

    std::string shared_secret;
    if (!derive_shared_secret(loadedPkey, peerKey, shared_secret)) {
        std::cerr << "Failed to derive shared secret" << std::endl;
        return 1;
    }

    std::string result;
    if (encrypt) {
        if (!AES_encrypt(text, shared_secret, result)) {
            std::cerr << "Encryption failed" << std::endl;
            return 1;
        }
    }
    else {
        if (!AES_decrypt(text, shared_secret, result)) {
            std::cerr << "Decryption failed" << std::endl;
            return 1;
        }
    }

    std::ofstream file_out("output_" + filename);
    file_out << result;
    file_out.close();

    std::cout << (encrypt ? "Encryption" : "Decryption") << " completed." << std::endl;

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(loadedPkey);
    EVP_PKEY_free(peerKey);
    return 0;
}
