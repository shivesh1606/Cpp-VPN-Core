// Encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

class Encryption {
private:
    char xorkey;

    // Private constructor to prevent direct instantiation
    Encryption() { xorkey = 'K'; }

public:
    // Delete copy constructor and assignment operator
    Encryption(const Encryption&) = delete;
    Encryption& operator=(const Encryption&) = delete;

    ~Encryption() {}

    // Public static method to get the single instance
    static Encryption& getInstance() {
        static Encryption instance; // Guaranteed to be created only once
        return instance;
    }

    void encrypt(const char data[], int len, char result[]) {
        for (int i = 0; i < len; i++)
            result[i] = data[i] ^ xorkey;
    }

    void decrypt(const char data[], int len, char result[]) {
        for (int i = 0; i < len; i++)
            result[i] = data[i] ^ xorkey;
    }
};

#endif
// encryption.cpp