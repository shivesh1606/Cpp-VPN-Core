#include "ClientSession.h"
#include <algorithm>
#include <iostream>
#include "utils/logger.h"
ClientSession::ClientSession() {
    LOG(LOG_INFO, "[+] ClientSession created\n");
}

ClientSession::~ClientSession() {
    LOG(LOG_INFO, "[+] ClientSession destroyed\n");
}

void ClientSession::addSession(const sockaddr_in& addr,
                               uint32_t client_magic,
                               uint32_t assigned_tun_ip,
                               uint32_t yc,
                               uint32_t b,uint32_t session_id) {
    SessionState s{};
    s.client_udp_addr = addr;
    s.client_magic = client_magic;
    s.assigned_tun_ip = assigned_tun_ip;
    s.created_at = time(nullptr);
    s.session_id = session_id;
    s.yc = yc;
    s.b = b;
    sessions_.push_back(s);
}

void ClientSession::eraseSession(const sockaddr_in& addr) {
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [&](const SessionState& s) {
                return s.client_udp_addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
                       s.client_udp_addr.sin_port == addr.sin_port;
            }),
        sessions_.end());
}

std::vector<uint32_t> ClientSession::eraseExpiredSessions(time_t timeout_sec) {
    time_t now = time(nullptr);
    std::vector<uint32_t> expired_ips;
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [&](const SessionState& s) {
                if ((now - s.created_at) > timeout_sec) {
                    expired_ips.push_back(s.assigned_tun_ip);
                    return true;
                }
                return false;
            }),
        sessions_.end());
    return expired_ips;
}

SessionState* ClientSession::getSession(const sockaddr_in& addr) {
    for (auto& s : sessions_) {
        if (s.client_udp_addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            s.client_udp_addr.sin_port == addr.sin_port) {
            return &s;
        }
    }
    return nullptr;
}
