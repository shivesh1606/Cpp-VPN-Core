// Windows test client for Cpp-VPN-Core — speaks protocol v1 (as on master):
//   HELLO / WELCOME / CLIENT_ACK / DATA / BYE / KEEPALIVE, toy DH (P=127) + 1-byte XOR.
// Modes:
//   tunnel (default) — Wintun adapter, routes, DNS, MTU, auto-reconnect. Needs Administrator + wintun.dll.
//   --probe          — handshake + keepalives + BYE only; no adapter, no admin. Prints timings.
// See clients/windows/README.md.

#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <iphlpapi.h>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <chrono>
#include "wintun.h"

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

static double now_ms()
{
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

// ======================== Shutdown flag ========================

static volatile bool g_running = true;

BOOL WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT)
    {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ======================== Config ========================

struct Config
{
    std::string server       = "127.0.0.1";
    int         port         = 5555;
    std::string log_file;
    int         log_level    = 2; // 0=ERROR,1=WARN,2=INFO,3=DEBUG
    int         mtu          = 1400;
    std::string dns;
    bool        reconnect    = true;
    int         reconnect_delay        = 5;
    int         reconnect_max_attempts = 0; // 0 = unlimited
    int         keepalive_interval     = 15; // matches Android app; server sweeps after 60 s
    // Protocol v1 server never sends anything to an idle client, so a receive timeout would
    // tear down healthy idle sessions. 0 = disabled (default). Only use with steady downstream traffic.
    int         timeout                = 0;
    bool        route_all_traffic      = false;
    // --probe mode
    bool        probe                  = false;
    int         probe_duration         = 20;  // seconds of keepalives before BYE
};

static std::string trim(const std::string &s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

static Config loadConfig(const char *path)
{
    Config cfg;
    std::ifstream f(path);
    if (!f.is_open()) return cfg;

    std::string line;
    while (std::getline(f, line))
    {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if      (key == "server")                cfg.server = val;
        else if (key == "port")                  cfg.port = std::stoi(val);
        else if (key == "log_file")              cfg.log_file = val;
        else if (key == "log_level")
        {
            if      (val == "error") cfg.log_level = 0;
            else if (val == "warn")  cfg.log_level = 1;
            else if (val == "info")  cfg.log_level = 2;
            else if (val == "debug") cfg.log_level = 3;
            else                     cfg.log_level = std::stoi(val);
        }
        else if (key == "mtu")                   cfg.mtu = std::stoi(val);
        else if (key == "dns")                   cfg.dns = val;
        else if (key == "reconnect")             cfg.reconnect = (val == "true" || val == "1");
        else if (key == "reconnect_delay")       cfg.reconnect_delay = std::stoi(val);
        else if (key == "reconnect_max_attempts") cfg.reconnect_max_attempts = std::stoi(val);
        else if (key == "keepalive_interval")    cfg.keepalive_interval = std::stoi(val);
        else if (key == "timeout")               cfg.timeout = std::stoi(val);
        else if (key == "route_all_traffic")     cfg.route_all_traffic = (val == "true" || val == "1");
        else if (key == "probe_duration")        cfg.probe_duration = std::stoi(val);
    }
    return cfg;
}

// ======================== Logging ========================

enum VpnLogLevel { VPN_ERROR = 0, VPN_WARN = 1, VPN_INFO = 2, VPN_DEBUG = 3 };

static int         g_log_level = VPN_INFO;
static FILE       *g_log_fp    = nullptr;
static const char *g_level_str[] = { "ERROR", "WARN", "INFO", "DEBUG" };

static void log_init(const Config &cfg)
{
    g_log_level = cfg.log_level;
    if (!cfg.log_file.empty())
    {
        g_log_fp = fopen(cfg.log_file.c_str(), "a");
        if (!g_log_fp)
            std::cerr << "[WARN] Could not open log file: " << cfg.log_file << "\n";
    }
}

static void log_shutdown()
{
    if (g_log_fp) { fflush(g_log_fp); fclose(g_log_fp); g_log_fp = nullptr; }
}

static void vpn_log(int level, const char *fmt, ...)
{
    if (level > g_log_level) return;

    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &t);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *lvl = (level >= 0 && level <= 3) ? g_level_str[level] : "???";
    fprintf(stderr, "[%s] [%s] %s\n", ts, lvl, msg);
    if (g_log_fp)
    {
        fprintf(g_log_fp, "[%s] [%s] %s\n", ts, lvl, msg);
        fflush(g_log_fp);
    }
}

#define LOG_E(fmt, ...) vpn_log(VPN_ERROR, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) vpn_log(VPN_WARN,  fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) vpn_log(VPN_INFO,  fmt, ##__VA_ARGS__)
#define LOG_D(fmt, ...) vpn_log(VPN_DEBUG, fmt, ##__VA_ARGS__)

// ======================== Protocol ========================

enum PacketType : uint8_t
{
    PKT_HELLO      = 1,
    PKT_WELCOME    = 2,
    PKT_CLIENT_ACK = 3,
    PKT_DATA       = 4,
    PKT_BYE        = 5,
    PKT_KEEPALIVE  = 6
};

#pragma pack(push, 1)
struct PacketHeader    { uint8_t type; uint32_t session_id; };
struct HelloPacket     { PacketHeader hdr; uint32_t client_magic; uint32_t yc; };
struct WelcomePacket   { PacketHeader hdr; uint32_t assigned_tun_ip; uint32_t ys; };
struct ClientAckPacket { PacketHeader hdr; };
#pragma pack(pop)

// ======================== DH crypto (P=127, G=9 — matches server) ========================

static const long long DH_P = 127;
static const long long DH_G = 9;

static long long modexp(long long base, long long exp, long long mod)
{
    long long result = 1;
    base %= mod;
    while (exp > 0)
    {
        if (exp & 1) result = result * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return result;
}

static uint8_t calculateXORKey(uint32_t s)
{
    return (uint8_t)((s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24)) & 0xFF);
}

// ======================== XOR cipher ========================

static void xorCrypt(const uint8_t *in, int len, uint8_t *out, uint8_t key)
{
    for (int i = 0; i < len; i++) out[i] = in[i] ^ key;
}

// ======================== Wintun function pointers ========================

static WINTUN_CREATE_ADAPTER_FUNC         *pCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC          *pCloseAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC       *pGetAdapterLuid;
static WINTUN_START_SESSION_FUNC          *pStartSession;
static WINTUN_END_SESSION_FUNC            *pEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC    *pGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC         *pReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *pReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC   *pAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC            *pSendPacket;

static bool loadWintun(HMODULE *out)
{
    HMODULE m = LoadLibraryA("wintun.dll");
    if (!m) { LOG_E("wintun.dll not found"); return false; }

#define LOAD(sym, type) \
    p##sym = reinterpret_cast<type*>(reinterpret_cast<void*>(GetProcAddress(m, "Wintun" #sym))); \
    if (!p##sym) { LOG_E("Missing Wintun" #sym); FreeLibrary(m); return false; }

    LOAD(CreateAdapter,         WINTUN_CREATE_ADAPTER_FUNC)
    LOAD(CloseAdapter,          WINTUN_CLOSE_ADAPTER_FUNC)
    LOAD(GetAdapterLuid,        WINTUN_GET_ADAPTER_LUID_FUNC)
    LOAD(StartSession,          WINTUN_START_SESSION_FUNC)
    LOAD(EndSession,            WINTUN_END_SESSION_FUNC)
    LOAD(GetReadWaitEvent,      WINTUN_GET_READ_WAIT_EVENT_FUNC)
    LOAD(ReceivePacket,         WINTUN_RECEIVE_PACKET_FUNC)
    LOAD(ReleaseReceivePacket,  WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
    LOAD(AllocateSendPacket,    WINTUN_ALLOCATE_SEND_PACKET_FUNC)
    LOAD(SendPacket,            WINTUN_SEND_PACKET_FUNC)
#undef LOAD

    *out = m;
    return true;
}

// ======================== TUN IP configuration ========================

static void configureTunIp(WINTUN_ADAPTER_HANDLE adapter, const char *ip_str)
{
    NET_LUID luid{};
    pGetAdapterLuid(adapter, &luid);

    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid       = luid;
    row.Address.si_family   = AF_INET;
    inet_pton(AF_INET, ip_str, &row.Address.Ipv4.sin_addr);
    row.OnLinkPrefixLength  = 24;
    row.DadState            = IpDadStatePreferred;

    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
        LOG_W("Could not set TUN IP (error %lu)", err);
    else
        LOG_I("TUN IP set to %s/24", ip_str);
}

// ======================== MTU configuration ========================

static void configureMtu(WINTUN_ADAPTER_HANDLE adapter, int mtu)
{
    NET_LUID luid{};
    pGetAdapterLuid(adapter, &luid);

    MIB_IPINTERFACE_ROW iface{};
    iface.Family        = AF_INET;
    iface.InterfaceLuid = luid;

    DWORD err = GetIpInterfaceEntry(&iface);
    if (err != NO_ERROR)
    {
        LOG_W("Could not get interface for MTU (error %lu)", err);
        return;
    }

    iface.NlMtu = (ULONG)mtu;
    iface.SitePrefixLength = 0;
    err = SetIpInterfaceEntry(&iface);
    if (err != NO_ERROR)
        LOG_W("Could not set MTU to %d (error %lu)", mtu, err);
    else
        LOG_I("MTU set to %d", mtu);
}

// ======================== DNS configuration ========================

static bool g_dns_configured = false;
static NET_LUID g_adapter_luid{};

static void configureDns(WINTUN_ADAPTER_HANDLE adapter, const std::string &dns_server)
{
    if (dns_server.empty()) return;

    pGetAdapterLuid(adapter, &g_adapter_luid);

    NET_IFINDEX ifIndex = 0;
    DWORD err = ConvertInterfaceLuidToIndex(&g_adapter_luid, &ifIndex);
    if (err != NO_ERROR)
    {
        LOG_W("Could not get interface index for DNS (error %lu)", err);
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ip set dns name=%lu static %s validate=no",
             (unsigned long)ifIndex, dns_server.c_str());

    int rc = system(cmd);
    if (rc != 0)
        LOG_W("DNS configuration failed (exit %d)", rc);
    else
    {
        LOG_I("DNS set to %s on interface %lu", dns_server.c_str(), (unsigned long)ifIndex);
        g_dns_configured = true;
    }
}

static void removeDns()
{
    if (!g_dns_configured) return;

    NET_IFINDEX ifIndex = 0;
    DWORD err = ConvertInterfaceLuidToIndex(&g_adapter_luid, &ifIndex);
    if (err != NO_ERROR) return;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ip set dns name=%lu dhcp", (unsigned long)ifIndex);
    system(cmd);
    g_dns_configured = false;
    LOG_D("DNS reverted to DHCP");
}

// ======================== Route management ========================

struct RouteState
{
    bool   vpn_subnet_added    = false;
    bool   default_route_added = false;
    bool   server_route_added  = false;
    ULONG  orig_gateway        = 0;
    ULONG  orig_if_index       = 0;
    ULONG  vpn_if_index        = 0;
    ULONG  server_addr         = 0;
};

static RouteState g_routes;

static bool getDefaultGateway(ULONG *gateway, ULONG *ifIndex)
{
    MIB_IPFORWARDTABLE *table = nullptr;
    ULONG size = 0;
    GetIpForwardTable(nullptr, &size, FALSE);
    table = (MIB_IPFORWARDTABLE *)malloc(size);
    if (!table) return false;

    DWORD err = GetIpForwardTable(table, &size, FALSE);
    if (err != NO_ERROR) { free(table); return false; }

    for (DWORD i = 0; i < table->dwNumEntries; i++)
    {
        if (table->table[i].dwForwardDest == 0 && table->table[i].dwForwardMask == 0)
        {
            *gateway = table->table[i].dwForwardNextHop;
            *ifIndex = table->table[i].dwForwardIfIndex;
            free(table);
            return true;
        }
    }
    free(table);
    return false;
}

static void addRoute(ULONG dest, ULONG mask, ULONG gateway, ULONG ifIndex, ULONG metric)
{
    MIB_IPFORWARDROW row{};
    row.dwForwardDest      = dest;
    row.dwForwardMask      = mask;
    row.dwForwardNextHop   = gateway;
    row.dwForwardIfIndex   = ifIndex;
    row.dwForwardType      = MIB_IPROUTE_TYPE_INDIRECT;
    row.dwForwardProto     = MIB_IPPROTO_NETMGMT;
    row.dwForwardMetric1   = metric;

    DWORD err = CreateIpForwardEntry(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
        LOG_W("Failed to add route (error %lu)", err);
}

static void deleteRoute(ULONG dest, ULONG mask, ULONG gateway, ULONG ifIndex)
{
    MIB_IPFORWARDROW row{};
    row.dwForwardDest      = dest;
    row.dwForwardMask      = mask;
    row.dwForwardNextHop   = gateway;
    row.dwForwardIfIndex   = ifIndex;
    row.dwForwardType      = MIB_IPROUTE_TYPE_INDIRECT;
    row.dwForwardProto     = MIB_IPPROTO_NETMGMT;

    DeleteIpForwardEntry(&row);
}

static void setupRoutes(WINTUN_ADAPTER_HANDLE adapter, const char *assigned_ip,
                         const Config &cfg)
{
    NET_LUID luid{};
    pGetAdapterLuid(adapter, &luid);
    ConvertInterfaceLuidToIndex(&luid, &g_routes.vpn_if_index);

    // VPN subnet route: 10.8.0.0/24 via TUN
    struct in_addr tun_addr{};
    inet_pton(AF_INET, assigned_ip, &tun_addr);
    ULONG subnet = tun_addr.s_addr & htonl(0xFFFFFF00);

    addRoute(subnet, htonl(0xFFFFFF00), tun_addr.s_addr, g_routes.vpn_if_index, 5);
    g_routes.vpn_subnet_added = true;
    LOG_I("Added route: VPN subnet via TUN adapter");

    if (cfg.route_all_traffic)
    {
        if (!getDefaultGateway(&g_routes.orig_gateway, &g_routes.orig_if_index))
        {
            LOG_W("Could not find default gateway — skipping full tunnel routing");
            return;
        }

        inet_pton(AF_INET, cfg.server.c_str(), &tun_addr);
        g_routes.server_addr = tun_addr.s_addr;

        // Host route for server via original gateway (prevent routing loop)
        addRoute(g_routes.server_addr, htonl(0xFFFFFFFF),
                 g_routes.orig_gateway, g_routes.orig_if_index, 1);
        g_routes.server_route_added = true;

        // Split default route: 0.0.0.0/1 + 128.0.0.0/1 via TUN (overrides 0/0 without deleting it)
        addRoute(htonl(0x00000000), htonl(0x80000000), tun_addr.s_addr, g_routes.vpn_if_index, 3);
        addRoute(htonl(0x80000000), htonl(0x80000000), tun_addr.s_addr, g_routes.vpn_if_index, 3);
        g_routes.default_route_added = true;
        LOG_I("Added default route via VPN (split tunnel)");
    }
}

static void teardownRoutes(const char *assigned_ip)
{
    struct in_addr tun_addr{};
    inet_pton(AF_INET, assigned_ip, &tun_addr);

    if (g_routes.default_route_added)
    {
        deleteRoute(htonl(0x00000000), htonl(0x80000000), tun_addr.s_addr, g_routes.vpn_if_index);
        deleteRoute(htonl(0x80000000), htonl(0x80000000), tun_addr.s_addr, g_routes.vpn_if_index);
        LOG_D("Removed default route");
    }
    if (g_routes.server_route_added)
    {
        deleteRoute(g_routes.server_addr, htonl(0xFFFFFFFF),
                     g_routes.orig_gateway, g_routes.orig_if_index);
        LOG_D("Removed server host route");
    }
    if (g_routes.vpn_subnet_added)
    {
        ULONG subnet = tun_addr.s_addr & htonl(0xFFFFFF00);
        deleteRoute(subnet, htonl(0xFFFFFF00), tun_addr.s_addr, g_routes.vpn_if_index);
        LOG_D("Removed VPN subnet route");
    }
    g_routes = RouteState{};
}

// ======================== Handshake ========================

static bool performHandshake(SOCKET sock, const sockaddr_in &server,
                              uint8_t &xor_key, uint32_t &session_id,
                              char assigned_ip[INET_ADDRSTRLEN])
{
    srand((unsigned)time(nullptr));
    uint32_t secret_b     = (uint32_t)(rand() % 4001 + 1000);
    uint32_t client_magic = (uint32_t)(rand() % 900000 + 100000);
    uint32_t yc           = (uint32_t)modexp(DH_G, secret_b, DH_P);

    HelloPacket hello{};
    hello.hdr.type        = PKT_HELLO;
    hello.hdr.session_id  = 0;
    hello.client_magic    = htonl(client_magic);
    hello.yc              = htonl(yc);

    // Same HELLO (same client_magic) on every retry: the server resends the identical WELCOME
    // for a duplicate HELLO (master fa857d9), so key and IP stay consistent across retries.
    for (int attempt = 1; attempt <= 4 && g_running; ++attempt)
    {
        double t0 = now_ms();
        sendto(sock, (char *)&hello, sizeof(hello), 0,
               (sockaddr *)&server, sizeof(server));
        LOG_I("Sent HELLO (attempt %d/4)", attempt);

        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        timeval tv{5, 0};
        if (select(0, &rf, nullptr, nullptr, &tv) <= 0) continue;

        unsigned char buf[2048];
        sockaddr_in from{};
        int fromLen = sizeof(from);
        int n = recvfrom(sock, (char *)buf, sizeof(buf), 0,
                         (sockaddr *)&from, &fromLen);
        if (n < (int)sizeof(WelcomePacket)) continue;

        PacketHeader *hdr = (PacketHeader *)buf;
        if (hdr->type != PKT_WELCOME) continue;
        double rtt = now_ms() - t0;

        WelcomePacket *welcome  = (WelcomePacket *)buf;
        session_id              = ntohl(welcome->hdr.session_id);
        uint32_t assigned_host  = ntohl(welcome->assigned_tun_ip);
        uint32_t ys             = ntohl(welcome->ys);

        uint32_t shared = (uint32_t)modexp(ys, secret_b, DH_P);
        xor_key = calculateXORKey(shared);

        ClientAckPacket ack{};
        ack.hdr.type       = PKT_CLIENT_ACK;
        ack.hdr.session_id = htonl(session_id);
        sendto(sock, (char *)&ack, sizeof(ack), 0,
               (sockaddr *)&server, sizeof(server));

        struct in_addr a{};
        a.s_addr = htonl(assigned_host);
        inet_ntop(AF_INET, &a, assigned_ip, INET_ADDRSTRLEN);

        LOG_I("Handshake done: session=%u ip=%s xor_key=%d hello->welcome=%.2f ms (attempt %d)",
              session_id, assigned_ip, (int)xor_key, rtt, attempt);
        return true;
    }
    return false;
}

// ======================== VPN session ========================

static void sendBye(SOCKET sock, const sockaddr_in &server, uint32_t session_id)
{
    PacketHeader bye{};
    bye.type       = PKT_BYE;
    bye.session_id = htonl(session_id);
    sendto(sock, (char *)&bye, sizeof(bye), 0, (sockaddr *)&server, sizeof(server));
    LOG_I("Sent BYE to server");
}

static int runTunnel(SOCKET sock, const sockaddr_in &server,
                      WINTUN_SESSION_HANDLE wintun_session,
                      uint8_t xor_key, uint32_t session_id,
                      const Config &cfg)
{
    HANDLE wintun_event = pGetReadWaitEvent(wintun_session);
    WSAEVENT udp_event  = WSACreateEvent();
    WSAEventSelect(sock, udp_event, FD_READ);

    HANDLE wait_handles[2] = { wintun_event, (HANDLE)udp_event };

    static uint8_t io_buf[2048];
    static uint8_t crypto_buf[2048];
    time_t last_keepalive = time(nullptr);
    time_t last_recv      = time(nullptr);

    LOG_I("VPN tunnel active — Ctrl+C to disconnect");

    int result = 0; // 0 = clean shutdown, 1 = timeout (reconnect)

    while (g_running)
    {
        DWORD wait_ms = (DWORD)(cfg.keepalive_interval * 1000);
        DWORD wait = WaitForMultipleObjects(2, wait_handles, FALSE, wait_ms);

        // ---- TUN -> UDP ----
        if (wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT)
        {
            DWORD pkt_size;
            BYTE *pkt;
            while ((pkt = pReceivePacket(wintun_session, &pkt_size)) != nullptr)
            {
                PacketHeader hdr{};
                hdr.type       = PKT_DATA;
                hdr.session_id = htonl(session_id);

                memcpy(io_buf, &hdr, sizeof(hdr));
                xorCrypt(pkt, (int)pkt_size, io_buf + sizeof(hdr), xor_key);

                sendto(sock, (char *)io_buf, (int)(sizeof(hdr) + pkt_size),
                       0, (sockaddr *)&server, sizeof(server));

                pReleaseReceivePacket(wintun_session, pkt);
                LOG_D("TUN->UDP %lu bytes", pkt_size);
            }
        }

        // ---- UDP -> TUN ----
        if (wait == WAIT_OBJECT_0 + 1)
        {
            WSAResetEvent(udp_event);

            sockaddr_in from{};
            int fromLen = sizeof(from);
            int n;
            while ((n = recvfrom(sock, (char *)io_buf, sizeof(io_buf), 0,
                                 (sockaddr *)&from, &fromLen)) > 0)
            {
                if (n < (int)sizeof(PacketHeader)) continue;
                PacketHeader *hdr = (PacketHeader *)io_buf;
                if (hdr->type != PKT_DATA) continue;

                last_recv = time(nullptr);

                int payload = n - (int)sizeof(PacketHeader);
                xorCrypt(io_buf + sizeof(PacketHeader), payload, crypto_buf, xor_key);

                BYTE *buf = pAllocateSendPacket(wintun_session, (DWORD)payload);
                if (buf)
                {
                    memcpy(buf, crypto_buf, payload);
                    pSendPacket(wintun_session, buf);
                }
                LOG_D("UDP->TUN %d bytes", payload);
            }
        }

        // ---- Keepalive ----
        time_t now = time(nullptr);
        if (now - last_keepalive >= cfg.keepalive_interval)
        {
            PacketHeader ka{};
            ka.type       = PKT_KEEPALIVE;
            ka.session_id = htonl(session_id);
            sendto(sock, (char *)&ka, sizeof(ka), 0,
                   (sockaddr *)&server, sizeof(server));
            last_keepalive = now;
            LOG_D("Sent keepalive");
        }

        // ---- Timeout detection ----
        if (cfg.timeout > 0 && (now - last_recv) > cfg.timeout)
        {
            LOG_W("No data from server for %d seconds — connection lost", cfg.timeout);
            result = 1;
            break;
        }
    }

    WSACloseEvent(udp_event);
    return result;
}

// ======================== Probe mode (no adapter, no admin) ========================

static int runProbe(const Config &cfg)
{
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) { LOG_E("Failed to create socket"); return 1; }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port   = htons((u_short)cfg.port);
    if (inet_pton(AF_INET, cfg.server.c_str(), &server.sin_addr) != 1)
    {
        LOG_E("Invalid server IP: %s", cfg.server.c_str());
        closesocket(sock);
        return 1;
    }

    uint8_t  xor_key    = 0;
    uint32_t session_id = 0;
    char     assigned_ip[INET_ADDRSTRLEN]{};

    if (!performHandshake(sock, server, xor_key, session_id, assigned_ip))
    {
        LOG_E("PROBE FAIL: no WELCOME from %s:%d after 4 attempts", cfg.server.c_str(), cfg.port);
        closesocket(sock);
        return 2;
    }

    LOG_I("Probe: sending KEEPALIVE every %d s for %d s", cfg.keepalive_interval, cfg.probe_duration);
    int sent = 0;
    for (int elapsed = 0; elapsed < cfg.probe_duration && g_running; elapsed++)
    {
        if (elapsed % std::max(cfg.keepalive_interval, 1) == 0)
        {
            PacketHeader ka{};
            ka.type       = PKT_KEEPALIVE;
            ka.session_id = htonl(session_id);
            sendto(sock, (char *)&ka, sizeof(ka), 0, (sockaddr *)&server, sizeof(server));
            sent++;
        }
        Sleep(1000);
    }

    sendBye(sock, server, session_id);
    closesocket(sock);
    LOG_I("PROBE OK: session=%u ip=%s keepalives=%d (server log should show handshake, then [BYE])",
          session_id, assigned_ip, sent);
    return 0;
}

static bool isElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &len);
    CloseHandle(token);
    return ok && elev.TokenIsElevated;
}

static void printUsage()
{
    std::cout <<
        "Usage: vpn_client [options] [SERVER] [PORT]\n"
        "  SERVER                Server IPv4 address (default 127.0.0.1)\n"
        "  PORT                  Server UDP port (default 5555)\n"
        "  --config FILE         Load key=value settings (see vpn_client.conf.example)\n"
        "  --probe               Handshake + keepalives + BYE only (no adapter, no admin)\n"
        "  --duration SEC        Probe duration before BYE (default 20)\n"
        "  --route-all           Send all IPv4 traffic through the tunnel (tunnel mode)\n"
        "  --log-level LEVEL     error | warn | info | debug\n"
        "  -h, --help            Show this help\n";
}

// ======================== Main ========================

int main(int argc, char *argv[])
{
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Precedence: defaults < config file < command line
    Config cfg;
    const char *config_path = nullptr;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config_path = argv[i + 1];
    if (config_path) cfg = loadConfig(config_path);

    int positional = 0;
    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc)          { ++i; }
        else if (a == "-h" || a == "--help")          { printUsage(); return 0; }
        else if (a == "--probe")                      { cfg.probe = true; }
        else if (a == "--duration" && i + 1 < argc)   { cfg.probe_duration = std::stoi(argv[++i]); }
        else if (a == "--route-all")                  { cfg.route_all_traffic = true; }
        else if (a == "--log-level" && i + 1 < argc)
        {
            std::string v = argv[++i];
            cfg.log_level = v == "error" ? 0 : v == "warn" ? 1 : v == "debug" ? 3 : 2;
        }
        else if (a.rfind("--", 0) == 0)               { std::cerr << "Unknown option " << a << "\n"; printUsage(); return 1; }
        else if (positional == 0)                     { cfg.server = a; positional++; }
        else if (positional == 1)                     { cfg.port = std::stoi(a); positional++; }
    }

    log_init(cfg);
    LOG_I("Cpp-VPN-Core Windows test client (protocol v1), mode=%s", cfg.probe ? "probe" : "tunnel");
    LOG_I("Server: %s:%d", cfg.server.c_str(), cfg.port);

    // ---- Winsock init ----
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (cfg.probe)
    {
        int rc = runProbe(cfg);
        WSACleanup();
        log_shutdown();
        return rc;
    }

    if (!isElevated())
    {
        LOG_E("Tunnel mode creates a Wintun adapter and needs an elevated (Administrator) terminal.");
        LOG_E("Use --probe to test the handshake without admin.");
        WSACleanup();
        return 1;
    }

    // ---- Load Wintun (once) ----
    HMODULE hWintun = nullptr;
    if (!loadWintun(&hWintun)) { WSACleanup(); return 1; }

    int reconnect_count = 0;

    // ======================== Connection loop (handles reconnect) ========================
    while (g_running)
    {
        // ---- Create UDP socket ----
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET)
        {
            LOG_E("Failed to create socket");
            break;
        }

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port   = htons((u_short)cfg.port);
        if (inet_pton(AF_INET, cfg.server.c_str(), &server.sin_addr) != 1)
        {
            LOG_E("Invalid server IP: %s", cfg.server.c_str());
            closesocket(sock);
            break;
        }

        // ---- Handshake ----
        uint8_t  xor_key    = 0;
        uint32_t session_id = 0;
        char     assigned_ip[INET_ADDRSTRLEN]{};

        if (!performHandshake(sock, server, xor_key, session_id, assigned_ip))
        {
            LOG_E("Handshake failed");
            closesocket(sock);

            if (!cfg.reconnect || !g_running) break;
            reconnect_count++;
            if (cfg.reconnect_max_attempts > 0 && reconnect_count >= cfg.reconnect_max_attempts)
            {
                LOG_E("Max reconnect attempts (%d) reached", cfg.reconnect_max_attempts);
                break;
            }
            LOG_I("Retrying in %d seconds... (attempt %d)", cfg.reconnect_delay, reconnect_count);
            for (int i = 0; i < cfg.reconnect_delay && g_running; i++) Sleep(1000);
            continue;
        }

        reconnect_count = 0;

        // ---- Create TUN adapter ----
        WINTUN_ADAPTER_HANDLE adapter = pCreateAdapter(L"CppVPN", L"Wintun", nullptr);
        if (!adapter)
        {
            LOG_E("Failed to create Wintun adapter — run as Administrator");
            closesocket(sock);
            break;
        }

        configureTunIp(adapter, assigned_ip);
        configureMtu(adapter, cfg.mtu);

        WINTUN_SESSION_HANDLE wintun_session = pStartSession(adapter, 0x400000);
        if (!wintun_session)
        {
            LOG_E("Failed to start Wintun session");
            pCloseAdapter(adapter);
            closesocket(sock);
            break;
        }

        configureDns(adapter, cfg.dns);
        setupRoutes(adapter, assigned_ip, cfg);

        // ---- Run tunnel ----
        int tunnel_result = runTunnel(sock, server, wintun_session,
                                       xor_key, session_id, cfg);

        // ---- Cleanup this session ----
        sendBye(sock, server, session_id);
        teardownRoutes(assigned_ip);
        removeDns();
        pEndSession(wintun_session);
        pCloseAdapter(adapter);
        closesocket(sock);

        if (tunnel_result == 0 || !cfg.reconnect || !g_running)
            break;

        // ---- Reconnect with backoff ----
        reconnect_count++;
        if (cfg.reconnect_max_attempts > 0 && reconnect_count >= cfg.reconnect_max_attempts)
        {
            LOG_E("Max reconnect attempts (%d) reached", cfg.reconnect_max_attempts);
            break;
        }

        int delay = cfg.reconnect_delay * (1 << std::min(reconnect_count - 1, 5));
        LOG_I("Reconnecting in %d seconds... (attempt %d)", delay, reconnect_count);
        for (int i = 0; i < delay && g_running; i++) Sleep(1000);
    }

    FreeLibrary(hWintun);
    WSACleanup();
    log_shutdown();
    LOG_I("Shutdown complete");
    return 0;
}
