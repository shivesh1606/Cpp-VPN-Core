// Test helper: an issuer key pair and signed tickets (design 03).
#ifndef TESTS_AUTH_TICKET_FIXTURE_H
#define TESTS_AUTH_TICKET_FIXTURE_H

#include <sodium.h>

#include <cstring>
#include <vector>

#include "auth/Ticket.h"
#include "crypto/backends/SodiumAead.h"

struct TestIssuer
{
    uint8_t key_id = 1;
    uint8_t sk[64], pk[32];
    explicit TestIssuer(uint8_t id = 1) : key_id(id)
    {
        crypto::sodiumReady();
        crypto_sign_keypair(pk, sk);
    }
    auth::IssuerKeys keys() const
    {
        auth::PublicKey p;
        std::memcpy(p.data(), pk, 32);
        return {{key_id, p}};
    }
    // A valid ticket for `device_pk`, tags 0b1, valid [now-100, now+3600).
    auth::Ticket ticket(const uint8_t device_pk[32], uint64_t now, uint32_t tags = 1) const
    {
        auth::Ticket t;
        t.key_id = key_id;
        t.tier = 0;
        for (int i = 0; i < 16; i++)
            t.user_id[i] = uint8_t(0xa0 + i);
        std::memcpy(t.device_pk, device_pk, 32);
        t.tags = tags;
        t.nbf = uint32_t(now - 100);
        t.exp = uint32_t(now + 3600);
        t.ticket_id = 0x1122334455667788ull;
        auth::sign(t, sk);
        return t;
    }
    std::vector<uint8_t> bytes(const auth::Ticket &t) const
    {
        std::vector<uint8_t> b(auth::kTicketLen);
        auth::encode(t, b.data());
        return b;
    }
};

#endif // TESTS_AUTH_TICKET_FIXTURE_H
