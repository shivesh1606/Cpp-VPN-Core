#include "crypto/CipherRegistry.h"

#include <algorithm>
#include <cstring>

#include "crypto/backends/AeadLock.h"
#include "crypto/backends/SodiumAead.h"
#include "crypto/backends/XorBackend.h"
#if CPPVPN_WITH_OPENSSL
#include "crypto/backends/OpenSslAead.h"
#endif

namespace crypto
{

CipherRegistry &CipherRegistry::instance()
{
    static CipherRegistry registry = [] {
        // Registration order = default implementation per algorithm (first wins) and the
        // algorithm preference order of algorithms(): ChaCha20-Poly1305, AES-256-GCM, xor.
        CipherRegistry r;
        const bool sodium = sodiumReady();
        if (sodium)
            r.add(std::make_unique<AeadBackend<SodiumChaCha20Poly1305>>());
#if CPPVPN_WITH_OPENSSL
        r.add(std::make_unique<AeadBackend<OpenSslChaCha20Poly1305>>());
#endif
        if (sodium && sodiumAes256GcmAvailable()) // runtime gate: hardware AES only
            r.add(std::make_unique<AeadBackend<SodiumAes256Gcm>>());
#if CPPVPN_WITH_OPENSSL
        r.add(std::make_unique<AeadBackend<OpenSslAes256Gcm>>());
#endif
        r.add(std::make_unique<XorBackend>()); // insecure; protocol v1 only
        return r;
    }();
    return registry;
}

bool CipherRegistry::add(std::unique_ptr<CipherBackend> backend)
{
    if (!backend || find(backend->algorithmId(), backend->implName()))
        return false;
    backends_.push_back(std::move(backend));
    return true;
}

const CipherBackend *CipherRegistry::find(uint8_t algorithm_id) const
{
    for (const auto &b : backends_)
        if (b->algorithmId() == algorithm_id)
            return b.get();
    return nullptr;
}

const CipherBackend *CipherRegistry::find(uint8_t algorithm_id, const char *impl_name) const
{
    if (!impl_name)
        return nullptr;
    for (const auto &b : backends_)
        if (b->algorithmId() == algorithm_id && std::strcmp(b->implName(), impl_name) == 0)
            return b.get();
    return nullptr;
}

std::vector<uint8_t> CipherRegistry::algorithms() const
{
    std::vector<uint8_t> ids;
    for (const auto &b : backends_)
        if (std::find(ids.begin(), ids.end(), b->algorithmId()) == ids.end())
            ids.push_back(b->algorithmId());
    return ids;
}

} // namespace crypto
