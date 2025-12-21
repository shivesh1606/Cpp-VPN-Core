#include "XorCipher.h"

void XorCipher::crypt(const char data[], int len, char result[], uint8_t &xorkey)
{
    for (int i = 0; i < len; i++)
        result[i] = data[i] ^ xorkey;
}