//
// Created by famgy on 19-2-28.
//

#include <string.h>
#include <malloc.h>
#include "transform.h"
#include "log.h"

/*
 * convert char to hexadecimal string
 */
void char2HexString(const unsigned char input[], size_t inputSize, unsigned char output[]){
    int i;
    unsigned char str[] = "0123456789abcdef";//hexadecimal byte

    for(i=0; i < inputSize; i++)
    {
        output[i*2] = str[(input[i] >> 4) & 0x0f];//将一个byte的高四位转成十六进制字符
        output[i*2+1] = str[input[i] & 0x0f];//将一个byte的低四位转成十六进制字符
    }

    //appending '\0' indicate the end of string
    output[inputSize * 2] = '\0';
}

/*
 * convert every ascii encoding char in input
 * to hexadecimal encoding
 * the size of input is unchanged.
 */
static void ascii2Hex(unsigned char *inOutPut){
    int i;
    int number;
    int size = strlen((const char *)inOutPut);

    for(i = 0; i < size; i++){

        //cast char to ascii decimal number
        number = (int)inOutPut[i];
        switch(number){
            case 97:
                inOutPut[i] = 0x0a;
                break;
            case 98:
                inOutPut[i] = 0x0b;
                break;
            case 99:
                inOutPut[i] = 0x0c;
                break;
            case 100:
                inOutPut[i] = 0x0d;
                break;
            case 101:
                inOutPut[i] = 0x0e;
                break;
            case 102:
                inOutPut[i] = 0x0f;
                break;
            case 48:
                inOutPut[i] = 0x00;
                break;
            case 49:
                inOutPut[i] = 0x01;
                break;
            case 50:
                inOutPut[i] = 0x02;
                break;
            case 51:
                inOutPut[i] = 0x03;
                break;
            case 52:
                inOutPut[i] = 0x04;
                break;
            case 53:
                inOutPut[i] = 0x05;
                break;
            case 54:
                inOutPut[i] = 0x06;
                break;
            case 55:
                inOutPut[i] = 0x07;
                break;
            case 56:
                inOutPut[i] = 0x08;
                break;
            case 57:
                inOutPut[i] = 0x09;
                break;
            default:
                break;
        }
    }

    //appending '\0' indicates the end of string
    inOutPut[size] = '\0';
}

int hexString2Binary(const unsigned char input[], unsigned int inputSize, unsigned char output[]){

    unsigned char *inOutPut = (unsigned char *)malloc(inputSize + 1);
    if (inOutPut == NULL) {
        log_print(ANDROID_LOG_DEBUG, "hexString2Char", "malloc failed");
        return -1;
    }

    memcpy(inOutPut, input, inputSize);
    inOutPut[inputSize] = '\0';
    ascii2Hex(inOutPut);

    for(int i = 0; i < inputSize/2; i++){
        output[i] = (inOutPut[i*2] << 4) | inOutPut[i*2+1];
    }

    //appending '\0' indicates the end of string.
    output[inputSize/2] = '\0';

    return 0;
}

