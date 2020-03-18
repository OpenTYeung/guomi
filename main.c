#include "encrypt.h"
#include <stdio.h>
#include <string.h>

int main()
{
    unsigned char hexHashValue[65];
    sm3HashString("888", 3, hexHashValue);
    printf("sm3:%s\n", hexHashValue);
    
    const unsigned char *plaintext="abcd1234";
    unsigned char mkey[16];
    memcpy(mkey, hexHashValue, 16);
    unsigned char * en = sm4EncryptTextWithKey(plaintext, mkey);
    unsigned char * de = sm4DecryptTextWithKey(en, mkey);
    printf("en:%s de=%s\n", en,de);
}
