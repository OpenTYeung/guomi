//
// Created by famgy on 18-10-24.
//

#ifndef CRYPTOSDK_LOG_H
#define CRYPTOSDK_LOG_H


extern "C" {
    
#define ANDROID_LOG_DEBUG 0

void log_print(int prio, const char* tag, const char* fmt, ...);
void printHex(const char *name, unsigned char *c, int n);

};

#endif //CRYPTOSDK_LOG_H
