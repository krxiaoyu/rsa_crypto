#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

const char* public_key_str =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAywUa53kz43xjvHT4QHt4\n"
	"WgZd2KIp6tLDDFexzhcKTFMxCgsg/Cbx50ttpO/yCXLs2SxZfuWkOdXiIlkeV8eW\n"
	"AM57zseBOMGKTA1siWAuQYjLy3VnXWdwVM97+JurNh1ykTfXj2S/Y4W5zrRkzzro\n"
	"CIe7xm+5CQ2YfF/KLnN+DFPP9aXBVd0n4hSKO0PAn8SGoabyu9UjQ2SjXfcMJKwL\n"
	"oeDTjMuZNuHYUPM+l8JYbIbVMGxud9enqMcbEocUSBhu1+5nrZzwOofrH7LBvl+l\n"
	"i8QX+nDN9fkU+OF27iw49/5sco8lwbbr0k9xeyhVGNhl0NVpfJ5YtHURFdqf1T8U\n"
	"6wIDAQAB\n"
	"-----END PUBLIC KEY-----\n";

const char* private_key_str =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIEogIBAAKCAQEAywUa53kz43xjvHT4QHt4WgZd2KIp6tLDDFexzhcKTFMxCgsg\n"
	"/Cbx50ttpO/yCXLs2SxZfuWkOdXiIlkeV8eWAM57zseBOMGKTA1siWAuQYjLy3Vn\n"
	"XWdwVM97+JurNh1ykTfXj2S/Y4W5zrRkzzroCIe7xm+5CQ2YfF/KLnN+DFPP9aXB\n"
	"Vd0n4hSKO0PAn8SGoabyu9UjQ2SjXfcMJKwLoeDTjMuZNuHYUPM+l8JYbIbVMGxu\n"
	"d9enqMcbEocUSBhu1+5nrZzwOofrH7LBvl+li8QX+nDN9fkU+OF27iw49/5sco8l\n"
	"wbbr0k9xeyhVGNhl0NVpfJ5YtHURFdqf1T8U6wIDAQABAoIBAFRuKBUxs6GcnoHG\n"
	"h2ORtaiC005/ij0tL46Xfct+i3rYciGCJVKYA6w0E0Ivw5GoaNWcew+qAxVGXMf6\n"
	"FgNdboWhWZ3SHGx1GMWuI4AyLqp0cISJq9YNaYrrytvGKXrU3kuEVLI+rNV/zJkp\n"
	"Lm98SPkbMb1Bw0r/i3XWBGgzAa2wA8JpA/glogTyRbEhlUoGF60Lwj7ZZZy00bED\n"
	"TKzH6bahbcn75uAPw3Ho0OnKQ5GdBPnqdHm3mNvz3xtBwPieaz6qHY/RCHhVh6g/\n"
	"eDb9ULD27u0WJMKZO+VH3wi1qqkTKZ0q2fxxMeNjawuBBaGwqdaY4GDQf4aWpuAr\n"
	"HWcXxKECgYEA5GFTbyPPZyx/YlC2stCywjxrxXvxzw4HCIsblPjdclnStVuvivXX\n"
	"mcmNrI1c6VlaSfjgQIbF+gaLZTE6GgqbZFaU9uT6nQXNsmMZXGdRxPnYU7JHF8aw\n"
	"Fj/Na4RdkttjeT9Afjvg3FmJqOxXvdWVJP7oioPv9aJ1SfUFcslLt5sCgYEA45Kf\n"
	"o4kQDWyNFN+PEca8A5RNu/BYDteEtmlsau58SQZGtv+8FOeMkG/bJDbxyWWeRBYM\n"
	"hMRP0ycWTtJGCLrQAjhWApQ3gfqAayjBethecSjil0y6J7eySIkyNhHf+Z2sSr9S\n"
	"KAz8sJcDsk6fvN/Fjd3Rt3pLEItq9ruFuf4fdPECgYBdka6gc3iPWgDa5BzmiHEk\n"
	"+aJiKBT7c1DYZD4pvAjmx/x3h5gVhAIQpS6his2NYamHcytV5KIKfVHxZMjcUIo4\n"
	"Au1HdqtjWDRdqRKD9GThIkhKillsWWBdzUg5i+LWv4Iy9AJVdez7+sdW6XZNdcuE\n"
	"e9gEoGfZKPWLFpNj4ytdjwKBgAZciunfYvt9FVSIC0/L5mWTN7kRNuTzUVpoCAfV\n"
	"MtQ3wLJM480Ry/QdrFqOzqN6m7n7g84STsjwRsddSWflEPt+56iazBJuFjjoor/0\n"
	"XG99XRgtpOaHVAyDCUxJo6EurypHvtwvwMCO+CN73ytAdh1JHhuq535G526OP2a7\n"
	"m9WBAoGAcse2PgtoHXnH5DR4RbcYJW7xpVyn6/4HO8XU9rBab+46tSvOVDVicTY5\n"
	"bdt+RBjzTYFldgwnDlVDgCIXVTq/EI7QZrgxrbkQNT5WULLF4wdPwy6QKTAZ/JzY\n"
	"ayQjG24QInzIwd6ZqHOweJvdRfoN2NaBeD0byWggiplKgutuLhI=\n"
	"-----END RSA PRIVATE KEY-----\n";
	
RSA *read_key_from_str(const char *filename, int is_private_key) {
    BIO* bio = BIO_new_mem_buf(filename, -1);
    if (bio == NULL) {
        printf("Failed to read %s.\n",filename);
        return NULL;
    }
	
    RSA *rsa_key = NULL;
    if (is_private_key) {
		rsa_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
		
    } else {
		rsa_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    }
    if (rsa_key == NULL) {
        printf("Failed to read %s.\n",filename);
        return NULL;
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
//    RSA *private_key = read_key_from_file("private_key.pem", 1);
	RSA *private_key = read_key_from_str(private_key_str, 1);
    RSA *public_key = read_key_from_str(public_key_str, 0);
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
    printf("Encrypted[%d]: ",encrypted_len);
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    // 释放资源
    RSA_free(private_key);
    RSA_free(public_key);

    return 0;
}
