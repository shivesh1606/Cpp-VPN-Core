// TicketAuthenticator.h - v2::Authenticator for auth.mode = ticket (design doc 03, sections 2, 6).
//
// Holds the node's verification inputs (issuer keys, node tag mask) and the current revocation
// list. Used only from the packet-loop thread: the fetcher thread hands bytes over, and
// applyRevocations() runs on the loop thread.
#ifndef AUTH_TICKETAUTHENTICATOR_H
#define AUTH_TICKETAUTHENTICATOR_H

#include <cstring>
#include <ctime>
#include <functional>

#include "auth/RevocationList.h"
#include "auth/Ticket.h"
#include "protocol/v2/Server.h"

namespace auth
{

class TicketAuthenticator : public v2::Authenticator
{
public:
    using Clock = std::function<uint64_t()>; // Unix seconds

    TicketAuthenticator(IssuerKeys issuers, uint32_t node_mask,
                        Clock clock = [] { return uint64_t(std::time(nullptr)); })
        : issuers_(std::move(issuers)), node_mask_(node_mask), clock_(std::move(clock))
    {
    }

    v2::AuthResult authenticate(const uint8_t s_c[32], const std::vector<uint8_t> &ticket) override
    {
        Ticket t;
        v2::AuthResult r;
        const Verdict v = verify(ticket.data(), ticket.size(), s_c, clock_(), issuers_, node_mask_,
                                 revocations_.current(), &t);
        r.reason = uint8_t(v);
        r.reason_name = verdictName(v);
        std::memcpy(r.user_id, t.user_id, sizeof(r.user_id));
        r.ticket_id = t.ticket_id;
        r.exp = t.exp;
        return r;
    }

    // Verifies and applies a revocation list (signature, newer seq). On success drops matching
    // sessions from `server` (BYE packets in `out`) and returns kOk; `dropped` gets the count.
    ListVerdict applyRevocations(const std::vector<uint8_t> &bytes, v2::Server *server, uint64_t now_ms,
                                 std::vector<v2::Server::Outgoing> &out, size_t &dropped)
    {
        dropped = 0;
        const ListVerdict v = revocations_.update(bytes.data(), bytes.size(), issuers_);
        if (v == ListVerdict::kOk && server)
        {
            const RevocationList *l = revocations_.current();
            dropped = server->revoke(
                [l](const uint8_t user_id[16], uint64_t ticket_id) {
                    return l->hasUser(user_id) || l->hasTicket(ticket_id);
                },
                now_ms, out);
        }
        return v;
    }

    const RevocationList *revocations() const { return revocations_.current(); }

private:
    IssuerKeys issuers_;
    uint32_t node_mask_;
    Clock clock_;
    RevocationState revocations_;
};

} // namespace auth

#endif // AUTH_TICKETAUTHENTICATOR_H
