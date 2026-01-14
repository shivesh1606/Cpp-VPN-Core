#ifndef CLIENTSESSION_H
#define CLIENTSESSION_H

#include <vector>
#include <netinet/in.h>
#include <ctime>


/*
Session state maintained per client after handshake.
*/
#pragma pack(push, 1)
struct SessionState
{
    sockaddr_in client_udp_addr;  // Client's real-world UDP address
    uint32_t client_magic;      // Echoed from HELLO
    uint32_t assigned_tun_ip; // server-assigned VPN IP (host order)
    time_t created_at;   // 👈 used for deletion of session state on HandshakeTime Expiry
    uint32_t yc;        // client's public value for Diffie-Hellman
    uint32_t b;      // server private key ✅
    uint32_t session_id; // Persistent session ID for roaming support
};
#pragma pack(pop)

class ClientSession {
public:
    ClientSession();
    ~ClientSession();

    void addSession(const sockaddr_in& addr,
                    uint32_t client_magic,
                    uint32_t assigned_tun_ip,
                    uint32_t yc,
                    uint32_t b,
                    uint32_t session_id);

    void eraseSession(const sockaddr_in& addr);
    void eraseExpiredSessions(time_t timeout_sec);
    SessionState* getSession(const sockaddr_in& addr);

private:
    std::vector<SessionState> sessions_;
};

#endif // CLIENTSESSION_H