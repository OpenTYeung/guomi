//
// Created by famgy on 19-2-28.
//

#ifndef CRYPTOSDK_ENCRYPT_H
#define CRYPTOSDK_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

unsigned char * sm4EncryptText(const unsigned char *plaintext);
unsigned char * sm4DecryptText(const unsigned char *ciphertext);
unsigned char * sm4EncryptTextWithKey(const unsigned char *plaintext, const unsigned char *mkey);
unsigned char * sm4DecryptTextWithKey(const unsigned char *cHexCiphertext, const unsigned char *mkey);
int sm4EncryptFile(const unsigned char *plainFilePath, const unsigned char *cipherFilePath);
int sm4DecryptFile(const unsigned char *cipherFilePath, const unsigned char *plainFilePath);
void sm3HashString(const unsigned char *text, size_t textSize,unsigned char *hexHashValue);
void sm3HashFile(const unsigned char *filePath, unsigned char *hexHashValue);

#ifdef __cplusplus
}
#endif

#endif //CRYPTOSDK_ENCRYPT_H
