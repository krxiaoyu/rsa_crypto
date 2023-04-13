#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

RSA *read_key_from_file(const char *filename, int is_private_key) {
    FILE *key_file = fopen(filename, "rb");
    if (key_file == NULL) {
        fprintf(stderr, "Failed to open the file %s\n", filename);
        return NULL;
    }

    RSA *rsa_key = NULL;
    if (is_private_key) {
        rsa_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    } else {
        rsa_key = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
    }

    fclose(key_file);

    if (rsa_key == NULL) {
        fprintf(stderr, "Failed to read RSA key from file %s\n", filename);
    }

    return rsa_key;
}

int rsa_encrypt(RSA *public_key, const unsigned char *plaintext, int plaintext_len, unsigned char *encrypted) {
    return RSA_public_encrypt(plaintext_len, plaintext, encrypted, public_key, RSA_PKCS1_PADDING);
}

int rsa_decrypt(RSA *private_key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *decrypted) {
    return RSA_private_decrypt(ciphertext_len, ciphertext, decrypted, private_key, RSA_PKCS1_PADDING);
}

int main() {
    // 读取公钥和私钥
    RSA *private_key = read_key_from_file("private_key.pem", 1);
    RSA *public_key = read_key_from_file("public_key.pem", 0);
    if (private_key == NULL || public_key == NULL) {
        return 1;
    }

    // 定义明文、密文和解密后的明文变量
    const char *plaintext = "Hello, RSA!";
    unsigned char encrypted[256] = {0};
    unsigned char decrypted[256] = {0};

    // 加密
    int encrypted_len = rsa_encrypt(public_key, (const unsigned char *)plaintext, strlen(plaintext), encrypted);
    if (encrypted_len == -1) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    // 解密
    int decrypted_len = rsa_decrypt(private_key, encrypted, encrypted_len, decrypted);
    if (decrypted_len == -1) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Plaintext: %s\n", plaintext);
    printf("Encrypted: ");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    // 释放资源
    RSA_free(private_key);
    RSA_free(public_key);

    return 0;
}
