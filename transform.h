//
// Created by famgy on 19-2-28.
//

#ifndef CRYPTOSDK_TRANSFORM_H
#define CRYPTOSDK_TRANSFORM_H

#include <cstdio>

extern "C" {

void char2HexString(const unsigned char input[], size_t inputSize, unsigned char output[]);
int hexString2Binary(const unsigned char input[], unsigned int inputSize,unsigned char output[]);



};

#endif //CRYPTOSDK_TRANSFORM_H
