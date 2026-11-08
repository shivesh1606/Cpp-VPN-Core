// CipherRegistry.h - Maps wire cipher_id -> available implementations (design doc 01, section 2.2).
//
// Backends compiled into the binary register here. Per-algorithm implementation choice and
// the server preference order come from node.conf (milestone M3); until then the first
// registered implementation of an algorithm is used.
#ifndef CRYPTO_CIPHERREGISTRY_H
#define CRYPTO_CIPHERREGISTRY_H

#include <memory>
#include <vector>

#include "crypto/SessionLock.h"

namespace crypto
{

class CipherRegistry
{
public:
    // Registry pre-populated with every backend compiled into this binary.
    static CipherRegistry &instance();

    // Registers a backend; returns false if this (algorithm, impl) pair already exists.
    bool add(std::unique_ptr<CipherBackend> backend);

    // First registered implementation of `algorithm_id`, or nullptr.
    const CipherBackend *find(uint8_t algorithm_id) const;
    // Specific implementation of `algorithm_id`, or nullptr.
    const CipherBackend *find(uint8_t algorithm_id, const char *impl_name) const;

    // Distinct algorithm ids, in registration order (basis for the HELLO cipher_offer[]).
    std::vector<uint8_t> algorithms() const;

    const std::vector<std::unique_ptr<CipherBackend>> &all() const { return backends_; }

private:
    std::vector<std::unique_ptr<CipherBackend>> backends_;
};

} // namespace crypto

#endif // CRYPTO_CIPHERREGISTRY_H
