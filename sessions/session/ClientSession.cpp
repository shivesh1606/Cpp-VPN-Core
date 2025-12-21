#include "ClientSession.h"
#include <algorithm>
#include <iostream>

ClientSession::ClientSession() {
    std::cout << "[INFO] ClientSession initialized\n";
}

ClientSession::~ClientSession() {
    std::cout << "[INFO] ClientSession destroyed\n";
}

void ClientSession::addSession(const sockaddr_in& addr,
                               uint32_t client_magic,
                               uint32_t assigned_tun_ip,
                               uint32_t yc,
                               uint32_t b) {
    SessionState s{};
    s.client_udp_addr = addr;
    s.client_magic = client_magic;
    s.assigned_tun_ip = assigned_tun_ip;
    s.created_at = time(nullptr);
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

void ClientSession::eraseExpiredSessions(time_t timeout_sec) {
    time_t now = time(nullptr);
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [&](const SessionState& s) {
                return (now - s.created_at) > timeout_sec;
            }),
        sessions_.end());
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
