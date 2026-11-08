// Cidr.h - IPv4 "address/prefix" parsing and the client pool derived from it (plan N5).
//
//   tun_cidr = 10.8.0.1/24
//     server (tun0) address  10.8.0.1
//     netmask                255.255.255.0
//     client pool            10.8.0.2 .. 10.8.0.254   (server + 1 .. broadcast - 1)
//
// All addresses are host byte order.
#ifndef NET_IP_CIDR_H
#define NET_IP_CIDR_H

#include <arpa/inet.h>

#include <cstdint>
#include <string>

namespace net
{

struct Ipv4Cidr
{
    uint32_t addr = 0; // the interface address as written (not the network address)
    int prefix = 0;

    uint32_t netmask() const { return prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix); }
    uint32_t network() const { return addr & netmask(); }
    uint32_t broadcast() const { return network() | ~netmask(); }
};

// Parses "a.b.c.d/n". Returns false (and sets `error`) on bad syntax, prefix outside 16..30
// (/16 caps the pool at 65533 clients; /30 is the smallest net with a client), or an address
// that is the network or broadcast address.
inline bool parseCidr(const std::string &text, Ipv4Cidr &out, std::string &error)
{
    const size_t slash = text.find('/');
    if (slash == std::string::npos)
    {
        error = "expected a.b.c.d/prefix";
        return false;
    }
    in_addr a{};
    if (inet_pton(AF_INET, text.substr(0, slash).c_str(), &a) != 1)
    {
        error = "invalid IPv4 address '" + text.substr(0, slash) + "'";
        return false;
    }
    const std::string p = text.substr(slash + 1);
    if (p.empty() || p.size() > 2 || p.find_first_not_of("0123456789") != std::string::npos)
    {
        error = "invalid prefix '" + p + "'";
        return false;
    }
    Ipv4Cidr c;
    c.addr = ntohl(a.s_addr);
    c.prefix = std::stoi(p);
    if (c.prefix < 16 || c.prefix > 30)
    {
        error = "prefix /" + p + " not supported (16..30)";
        return false;
    }
    if (c.addr == c.network() || c.addr == c.broadcast())
    {
        error = "address is the network or broadcast address of /" + p;
        return false;
    }
    out = c;
    return true;
}

// Client pool = server address + 1 .. broadcast - 1. Size 0 if the server is the last host.
inline uint32_t poolStart(const Ipv4Cidr &c) { return c.addr + 1; }
inline uint32_t poolSize(const Ipv4Cidr &c)
{
    return c.broadcast() > c.addr + 1 ? c.broadcast() - (c.addr + 1) : 0;
}

inline std::string ipv4ToString(uint32_t host)
{
    in_addr a{};
    a.s_addr = htonl(host);
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

} // namespace net

#endif // NET_IP_CIDR_H
