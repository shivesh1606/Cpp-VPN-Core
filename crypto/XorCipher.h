// XorCipher.h
#include <cstdint>
#ifndef XORCIPHER_H
#define XORCIPHER_H

class XorCipher {
private:
    // Private constructor to prevent direct instantiation
    XorCipher() {  }

public:
    // Delete copy constructor and assignment operator
    XorCipher(const XorCipher&) = delete;
    XorCipher& operator=(const XorCipher&) = delete;

    ~XorCipher() {}

    // Public static method to get the single instance
    static XorCipher& getInstance() {
        static XorCipher instance; // Guaranteed to be created only once
        return instance;
    }

    void crypt(const char data[], int len, char result[],uint8_t &xorkey);
};

#endif