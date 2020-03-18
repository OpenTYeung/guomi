//
// Created by famgy on 19-2-28.
//

#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "encrypt.h"
#include "sm3.h"
#include "sm4.h"
#include "transform.h"

#define log_print(a,b,c)



#define BLOCK_SIZE 64
#define HASH_VALUE_SIZE 32

/*
 * sm4 security key is used to encrypt plain text and decrypt cipher text
 * the length of key is 128 bits = 16 bytes
 */
static unsigned char key[16] = { 0x26, 0x67, 0x3b, 0x31, 0x3f, 0x66, 0x30, 0x57, 0x2f, 0x3d, 0x52, 0x38, 0x36, 0x66, 0x40, 0x2a };


static unsigned char *padding(const unsigned char *input, int inLen, int *outLen, bool isEncrypt) {
    if (input == NULL) {
        *outLen = 0;
        return NULL;
    }

    unsigned char *buff = NULL;
    int mLen = 0;
    if (true == isEncrypt) {
        unsigned char pLen = 16 - inLen % 16;
        mLen = inLen + pLen;
        buff = (unsigned char *)malloc(mLen + 1);
        if (buff == NULL) {
            *outLen = -1;
            return NULL;
        }

        memcpy(buff, input, inLen);
        for (int i = 0; i < pLen; i++) {
            buff[inLen + i] = pLen;
        }
    } else {
        unsigned char pLen = input[inLen - 1];
        if (pLen > 16) {
            return NULL;
        }

        mLen = inLen - pLen;
        buff = (unsigned char *)malloc(mLen + 1);
        if (buff == NULL) {
            *outLen = -1;
            return NULL;
        }

        memcpy(buff, input, mLen);
    }

    *outLen = mLen;
    buff[mLen] = '\0';

    return buff;
}

static void sm4Encrypt(unsigned char input[], size_t inputSize, unsigned char output[]) {
    sm4_context sm4Context;

    sm4_setkey_enc(&sm4Context, key);
    sm4_crypt_ecb(&sm4Context, SM4_ENCRYPT, inputSize, input, output);
}

static void sm4Decrypt(unsigned char input[], size_t inputSize, unsigned char output[]) {
    sm4_context sm4Context;

    sm4_setkey_dec(&sm4Context, key);
    sm4_crypt_ecb(&sm4Context, SM4_DECRYPT, inputSize, input, output);
}

static void sm4EncryptWithKey(const unsigned char *mkey, unsigned char input[], size_t inputSize, unsigned char output[]) {
    sm4_context sm4Context;

    unsigned char newKey[16];
    memcpy(newKey, key, 16);
    for (int i = 0; i < strlen((const char*)mkey) && i < 16; i++) {
        newKey[i] = mkey[i];
    }

    sm4_setkey_enc(&sm4Context, newKey);
    sm4_crypt_ecb(&sm4Context, SM4_ENCRYPT, inputSize, input, output);
}

static void sm4DecryptWithKey(const unsigned char *mkey, unsigned char input[], size_t inputSize, unsigned char output[]) {
    sm4_context sm4Context;

    unsigned char newKey[16];
    memcpy(newKey, key, 16);
    for (int i = 0; i < strlen((const char*)mkey) && i < 16; i++) {
        newKey[i] = mkey[i];
    }

    sm4_setkey_dec(&sm4Context, newKey);
    sm4_crypt_ecb(&sm4Context, SM4_DECRYPT, inputSize, input, output);
}

unsigned char * sm4EncryptText(const unsigned char *plaintext){
    //check parameters
    if(plaintext == NULL) {
        return NULL;
    }

    int oContentLen = 0;
    unsigned char *oContent = padding(plaintext, strlen((char*)plaintext), &oContentLen, true);
    if (oContent == NULL) {
        return NULL;
    }

    unsigned char *nonHexCiphertext = (unsigned char *)malloc(oContentLen + 1);
    if (nonHexCiphertext == NULL) {
        free(oContent);
        return NULL;
    }

    sm4Encrypt(oContent, oContentLen, nonHexCiphertext);
    nonHexCiphertext[oContentLen] = '\0';
    free(oContent);

    unsigned char *hexCiphertext = (unsigned char *)malloc(oContentLen * 2 + 1);
    if (hexCiphertext == NULL) {
        free(nonHexCiphertext);
        return NULL;
    }

    char2HexString(nonHexCiphertext, oContentLen, hexCiphertext);
    free(nonHexCiphertext);

    return hexCiphertext;
}

unsigned char * sm4DecryptText(const unsigned char *cHexCiphertext){
    //check parameters
    if(cHexCiphertext == NULL) {
        return NULL;
    }

    int cHexCiphertextLen = strlen((char*)cHexCiphertext);
    int oContentLen = cHexCiphertextLen / 2;
    unsigned  char *cipherContent = (unsigned  char *)malloc(oContentLen + 1);
    if (cipherContent == NULL) {
        return NULL;
    }

    int iRet = hexString2Binary(cHexCiphertext, cHexCiphertextLen, cipherContent);
    if (iRet != 0) {
        free(cipherContent);
        return NULL;
    }

    unsigned char *plaintContent = (unsigned char *)malloc(oContentLen + 1);
    if (plaintContent == NULL) {
        free(cipherContent);
        return NULL;
    }

    sm4Decrypt(cipherContent, oContentLen, plaintContent);
    plaintContent[oContentLen] = '\0';
    free(cipherContent);

    int cPlaintextLen = 0;
    unsigned char *cPlantText = padding(plaintContent, oContentLen, &cPlaintextLen, false);
    free(plaintContent);
    if (cPlantText == NULL) {
        return NULL;
    }

    return cPlantText;
}

unsigned char * sm4EncryptTextWithKey(const unsigned char *plaintext, const unsigned char *mkey) {
    //check parameters
    if(plaintext == NULL) {
        return NULL;
    }

    int oContentLen = 0;
    unsigned char *oContent = padding(plaintext, strlen((char*)plaintext), &oContentLen, true);
    if (oContent == NULL) {
        return NULL;
    }

    unsigned char *nonHexCiphertext = (unsigned char *)malloc(oContentLen + 1);
    if (nonHexCiphertext == NULL) {
        free(oContent);
        return NULL;
    }

    sm4EncryptWithKey(mkey, oContent, oContentLen, nonHexCiphertext);
    nonHexCiphertext[oContentLen] = '\0';
    free(oContent);

    unsigned char *hexCiphertext = (unsigned char *)malloc(oContentLen * 2 + 1);
    if (hexCiphertext == NULL) {
        free(nonHexCiphertext);
        return NULL;
    }

    char2HexString(nonHexCiphertext, oContentLen, hexCiphertext);
    free(nonHexCiphertext);

    return hexCiphertext;
}

unsigned char * sm4DecryptTextWithKey(const unsigned char *cHexCiphertext, const unsigned char *mkey) {
    //check parameters
    if(cHexCiphertext == NULL) {
        return NULL;
    }

    int cHexCiphertextLen = strlen((char*)cHexCiphertext);
    int oContentLen = cHexCiphertextLen / 2;
    unsigned  char *cipherContent = (unsigned  char *)malloc(oContentLen + 1);
    if (cipherContent == NULL) {
        return NULL;
    }

    int iRet = hexString2Binary(cHexCiphertext, cHexCiphertextLen, cipherContent);
    if (iRet != 0) {
        free(cipherContent);
        return NULL;
    }

    unsigned char *plaintContent = (unsigned char *)malloc(oContentLen + 1);
    if (plaintContent == NULL) {
        free(cipherContent);
        return NULL;
    }

    sm4DecryptWithKey(mkey, cipherContent, oContentLen, plaintContent);
    plaintContent[oContentLen] = '\0';
    free(cipherContent);

    int cPlaintextLen = 0;
    unsigned char *cPlantText = padding(plaintContent, oContentLen, &cPlaintextLen, false);
    free(plaintContent);
    if (cPlantText == NULL) {
        return NULL;
    }

    return cPlantText;
}

int sm4EncryptFile(const unsigned char *plainFilePath, const unsigned char *cipherFilePath) {
    int iRet = 0;

    //Check parameters
    if(plainFilePath == NULL) {
        return -1;
    }

    if(cipherFilePath == NULL) {
        return -1;
    }

    //check for file existence
    if((access((const char*)plainFilePath, F_OK)) != 0) {
        return -1;
    }

    struct stat statbuff;
    stat((char*)plainFilePath, &statbuff);
    int plainFileSize = statbuff.st_size;

    //check for file read permission
    if((access((const char*)plainFilePath, R_OK)) != 0) {
        log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "plainFilePath does not have read permission..");
        return -1;
    }

    //if cipherFilePath exists,then remove it.
    if((access((const char*)cipherFilePath, F_OK)) == 0) {
        if(remove((const char*)cipherFilePath ) != 0 ) {
            log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "Error deleting cipherFilePath...");
            return -1;
        } else {
            log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "cipherFilePath is successfully deleted...");
        }
    }

    FILE *plainFile = fopen((const char*)plainFilePath, "rb");
    if(NULL == plainFile) {
        log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "open plain text file fail...");
        return -1;
    }

    FILE *ciphertFile = fopen((const char*)cipherFilePath, "ab");
    if(NULL == ciphertFile) {
        fclose(plainFile);
        log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "open cipher text file fail...");
        return -1;
    }

    //Write encrypt body
    unsigned char plaintBuffer[BLOCK_SIZE]={0};
    unsigned char cipherBuffer[BLOCK_SIZE]={0};
    int readBufferLen;

    int padLen = 0;
    unsigned char *padBuf = NULL;
    int hasReadLen = 0;
    while ((readBufferLen = fread(plaintBuffer, 1, BLOCK_SIZE, plainFile)) > 0) {
        hasReadLen += readBufferLen;
        if (readBufferLen == BLOCK_SIZE) {
            if (hasReadLen != plainFileSize) {
                sm4Encrypt(plaintBuffer, readBufferLen, cipherBuffer);
                fwrite(cipherBuffer, 1, readBufferLen, ciphertFile);
            } else {
                padBuf = padding(plaintBuffer, readBufferLen, &padLen, true);
                if (padBuf != NULL) {
                    sm4Encrypt(padBuf, padLen, cipherBuffer);
                    free(padBuf);

                    fwrite(cipherBuffer, 1, padLen, ciphertFile);
                } else {
                    log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "padding failed");
                    iRet = -1;
                }

                break;
            }
        } else {
            if (hasReadLen == plainFileSize) {
                padBuf = padding(plaintBuffer, readBufferLen, &padLen, true);
                if (padBuf != NULL) {
                    sm4Encrypt(padBuf, padLen, cipherBuffer);
                    free(padBuf);

                    fwrite(cipherBuffer, 1, padLen, ciphertFile);
                } else {
                    log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "padding failed");
                    iRet = -1;
                }
            } else {
                log_print(ANDROID_LOG_DEBUG, "sm4EncryptFile", "Not read finished, but is not equal BLOCK_SIZE");
                iRet = -1;
            }

            break;
        }
    }

    fclose(plainFile);
    fclose(ciphertFile);

    return iRet;
}

int sm4DecryptFile(const unsigned char *cipherFilePath, const unsigned char *plainFilePath) {
    int iRet = 0;

    //Check parameters
    if(plainFilePath == NULL) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "plainFilePath argument is null...");
        return -1;
    }

    if(cipherFilePath == NULL) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "cipherFilePath argument is null...");
        return -1;
    }

    //check for file existence
    if((access((const char*)cipherFilePath, F_OK)) != 0) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "cipherFilePath does not exist...");
        return -1;
    }

    struct stat statbuff;
    stat((char*)cipherFilePath, &statbuff);
    int cipherFileSize = statbuff.st_size;
    if (cipherFileSize % 16 != 0) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "cipherFileSize % 16 is not 0, return");
        return -1;
    }

    //check for file read permission
    if((access((const char*)cipherFilePath, R_OK)) != 0) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "cipherFilePath does not have read permission...");
        return -1;
    }

    //if cipherFilePath exists,then remove it.
    if((access((const char*)plainFilePath, F_OK)) == 0) {
        if( remove((const char*)plainFilePath ) != 0 ) {
            log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "Error deleting plainFilePath...");
            return -1;
        } else {
            log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "plainFilePath is successfully deleted...");
        }
    }

    /*
     * Open ciphertextFilePath for input operations. The file must exist.
     * 'r' character indicates read operation.
     * 'a' character indicates appending data at the end of file.
     * In order to open a file as a binary file, a "b" character has to be included
     */
    FILE *cipherFile = fopen((const char*)cipherFilePath, "rb");
    if(NULL == cipherFile) {
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "open plain text file fail...");
        return -1;
    }

    FILE *plainFile = fopen((const char*)plainFilePath, "ab");
    if(NULL == plainFile) {
        fclose(cipherFile);
        log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "open cipher text file fail...");
        return -1;
    }

    //Write encrypt body
    unsigned char plaintBuffer[BLOCK_SIZE]={0};
    unsigned char cipherBuffer[BLOCK_SIZE]={0};
    int readBufferLen;
    int hasReadLen = 0;
    while((readBufferLen = fread(cipherBuffer, 1, BLOCK_SIZE, cipherFile)) > 0) {
        hasReadLen += readBufferLen;
        if (readBufferLen == BLOCK_SIZE) {
            if (hasReadLen != cipherFileSize) {
                sm4Decrypt(cipherBuffer, BLOCK_SIZE, plaintBuffer);
                fwrite(plaintBuffer, 1, BLOCK_SIZE, plainFile);
            } else {
                //read finish
                sm4Decrypt(cipherBuffer, readBufferLen, plaintBuffer);
                int noPadLen = 0;
                unsigned char *noPadBuf = padding(plaintBuffer, readBufferLen, &noPadLen, false);
                if (noPadBuf != NULL) {
                    fwrite(noPadBuf, 1, noPadLen, plainFile);
                    free(noPadBuf);
                } else {
                    log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "padding failed");
                    iRet = -1;
                    break;
                }
            }
        } else {
            if (hasReadLen == cipherFileSize) {
                //read finish
                sm4Decrypt(cipherBuffer, readBufferLen, plaintBuffer);
                int noPadLen = 0;
                unsigned char *noPadBuf = padding(plaintBuffer, readBufferLen, &noPadLen, false);
                if (noPadBuf != NULL) {
                    fwrite(noPadBuf, 1, noPadLen, plainFile);
                    free(noPadBuf);
                } else {
                    log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "padding failed");
                    iRet = -1;
                }
            } else {
                log_print(ANDROID_LOG_DEBUG, "sm4DecryptFile", "failed, readBufferLen is not equal BLOCK_SIZE, and not read finish");
            }

            break;
        }
    }

    //close file stream.
    fclose(cipherFile);
    fclose(plainFile);

    return iRet;
}

/**
 * Convert arbitrary length text to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashString(const unsigned char *text, size_t textSize,unsigned char *hexHashValue) {
    //check parameters
    if(text == NULL) {
        perror("text argument is null...");
        return;
    }

    if(hexHashValue == NULL) {
        perror("hexHashValue argument is null...");
        return;
    }

    //allocating a 32 bytes(256 bits)size memory to store sm3 hash value.
    unsigned char *hashValue = (unsigned char *)malloc(HASH_VALUE_SIZE + 1);

    sm3((unsigned char*)text, textSize, hashValue);

    //appending '\0' to indicates the end.
    hashValue[HASH_VALUE_SIZE] = '\0';

    //convert hash value to hexadecimal type.
    char2HexString(hashValue, HASH_VALUE_SIZE, hexHashValue);

    //free unused memory
    free((void*) hashValue);

    return;
}

/**
 * Convert the file which is indicated by filePath to a fixed 256 bits length text.
 * Convert hash text to hexadecimal hash text.
 */
void sm3HashFile(const unsigned char *filePath, unsigned char *hexHashValue) {
    //check parameters
    if(filePath == NULL) {
        perror("invalid filePath argument is null...\n");
        return;
    }

    //check for file existence
    if((access((const char*)filePath, F_OK)) != 0) {
        perror("filePath does not exist...\n");
        return;
    }

    //check file read permission
    if((access((const char*)filePath, R_OK)) != 0) {
        perror("current process does not have read permission...\n");
        return;
    }

    if(hexHashValue == NULL) {
        perror("invalid hexHashValue argument is null...\n");
        return;
    }

    //allocating a 32 bytes(256 bits)size memory to store sm3 hash value.
    unsigned char *hashValue = (unsigned char *)malloc(HASH_VALUE_SIZE + 1);

    sm3_file((char *)filePath, hashValue);

    //appending '\0' to indicates the end.
    hashValue[HASH_VALUE_SIZE] = '\0';

    //convert hash value to hexadecimal type.
    char2HexString(hashValue, HASH_VALUE_SIZE, hexHashValue);

    //free unused memory
    free((void*) hashValue);

    return;
}
