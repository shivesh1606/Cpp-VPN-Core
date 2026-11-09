// RevocationList.h - signed revocation list (design doc 03, section 6). Portable.
//
//  | ver u8 | key_id u8 | seq u64 | issued_at u32 | count u32 | entries[count] {kind u8, id 16 B} | sig 64 |
//  kind 1 = user_id (16 B), 2 = ticket_id (u64 little-endian, zero-padded to 16 B)
//  sig = Ed25519(issuer_sk[key_id], "cppvpn-revocation-v1" || body)   (body = everything before sig)
//
// RevocationState keeps the current list and accepts a new one only if its signature is valid and
// its seq is greater than the current one (no rollback, section 6).
#ifndef AUTH_REVOCATIONLIST_H
#define AUTH_REVOCATIONLIST_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "auth/Ticket.h"

namespace auth
{

constexpr uint8_t kRevocationVersion = 1;
constexpr const char *kRevocationContext = "cppvpn-revocation-v1";
constexpr size_t kMaxRevocationEntries = 100000; // 1.7 MB; far above any Phase 0 need

class RevocationList
{
public:
    uint8_t key_id = 0;
    uint64_t seq = 0;
    uint32_t issued_at = 0;

    void addUser(const uint8_t user_id[kUserIdLen]);
    void addTicket(uint64_t ticket_id);
    bool hasUser(const uint8_t user_id[kUserIdLen]) const;
    bool hasTicket(uint64_t ticket_id) const { return tickets_.count(ticket_id) != 0; }
    size_t size() const { return users_.size() + tickets_.size(); }
    const std::set<std::string> &users() const { return users_; }
    const std::set<uint64_t> &tickets() const { return tickets_; }

    // Serializes and signs (vpnctl). Entries are written in sorted order (deterministic).
    std::vector<uint8_t> encodeSigned(const uint8_t issuer_sk[64]) const;

private:
    std::set<std::string> users_; // 16-byte user ids
    std::set<uint64_t> tickets_;
};

enum class ListVerdict : uint8_t
{
    kOk = 0,
    kFormat,
    kUnknownKey,
    kSig,
    kRollback, // seq not greater than the current list
};
const char *listVerdictName(ListVerdict v);

// Parses and verifies a list (signature only, no seq rule).
ListVerdict parseRevocationList(const uint8_t *p, size_t len, const IssuerKeys &issuers, RevocationList &out);

class RevocationState
{
public:
    // Replaces the current list if the new one is valid and has a greater seq.
    ListVerdict update(const uint8_t *p, size_t len, const IssuerKeys &issuers);
    const RevocationList *current() const { return current_.get(); }

private:
    std::unique_ptr<RevocationList> current_;
};

} // namespace auth

#endif // AUTH_REVOCATIONLIST_H
