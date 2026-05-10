// Windows VPN client — Wintun + real DH handshake + XOR encryption
// Requires: wintun.dll in the same directory, run as Administrator

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include "wintun.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ---- Shutdown flag ----
static volatile bool g_running = true;

BOOL WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT)
    {
        std::cout << "\n[INFO] Shutting down...\n";
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ---- Protocol ----
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

// ---- DH crypto (same params as server: P=127, G=9) ----
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

// ---- XOR cipher ----
static void xorCrypt(const uint8_t *in, int len, uint8_t *out, uint8_t key)
{
    for (int i = 0; i < len; i++) out[i] = in[i] ^ key;
}

// ---- Wintun function pointers ----
static WINTUN_CREATE_ADAPTER_FUNC        *pCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC         *pCloseAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC      *pGetAdapterLuid;
static WINTUN_START_SESSION_FUNC         *pStartSession;
static WINTUN_END_SESSION_FUNC           *pEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC   *pGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC        *pReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *pReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC  *pAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC           *pSendPacket;

static bool loadWintun(HMODULE *out)
{
    HMODULE m = LoadLibraryA("wintun.dll");
    if (!m) { std::cerr << "[ERROR] wintun.dll not found\n"; return false; }

#define LOAD(sym, type) \
    p##sym = (type*)GetProcAddress(m, "Wintun" #sym); \
    if (!p##sym) { std::cerr << "[ERROR] Missing Wintun" #sym "\n"; FreeLibrary(m); return false; }

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

// ---- Configure TUN IP via IP Helper API ----
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
        std::cerr << "[WARN] Could not set TUN IP (error " << err << ")\n";
    else
        std::cout << "[INFO] TUN IP set to " << ip_str << "/24\n";
}

// ---- Handshake (4 attempts, 5s timeout each) ----
static bool performHandshake(SOCKET sock, const sockaddr_in &server,
                              uint8_t &xor_key, uint32_t &session_id,
                              char assigned_ip[INET_ADDRSTRLEN])
{
    srand((unsigned)time(nullptr));
    uint32_t secret_b    = (uint32_t)(rand() % 4001 + 1000);
    uint32_t client_magic = (uint32_t)(rand() % 900000 + 100000);
    uint32_t yc          = (uint32_t)modexp(DH_G, secret_b, DH_P);

    HelloPacket hello{};
    hello.hdr.type        = PKT_HELLO;
    hello.hdr.session_id  = 0;
    hello.client_magic    = htonl(client_magic);
    hello.yc              = htonl(yc);

    for (int attempt = 1; attempt <= 4 && g_running; ++attempt)
    {
        sendto(sock, (char *)&hello, sizeof(hello), 0,
               (sockaddr *)&server, sizeof(server));
        std::cout << "[INFO] Sent HELLO (attempt " << attempt << ")\n";

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

        std::cout << "[INFO] Handshake done — session=" << session_id
                  << " ip=" << assigned_ip
                  << " xor_key=" << (int)xor_key << "\n";
        return true;
    }
    return false;
}

int main(int argc, char *argv[])
{
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    const char *server_ip  = (argc >= 2) ? argv[1] : "127.0.0.1";
    int server_port        = (argc >= 3) ? std::stoi(argv[2]) : 5555;

    std::cout << "[INFO] Connecting to " << server_ip << ":" << server_port << "\n";

    // ---- Winsock ----
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        std::cerr << "[ERROR] Failed to create socket\n";
        return 1;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port   = htons((u_short)server_port);
    if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1)
    {
        std::cerr << "[ERROR] Invalid server IP: " << server_ip << "\n";
        return 1;
    }

    // ---- Handshake ----
    uint8_t  xor_key    = 0;
    uint32_t session_id = 0;
    char     assigned_ip[INET_ADDRSTRLEN]{};

    if (!performHandshake(sock, server, xor_key, session_id, assigned_ip))
    {
        std::cerr << "[ERROR] Handshake failed after 4 attempts\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // ---- Load Wintun ----
    HMODULE hWintun = nullptr;
    if (!loadWintun(&hWintun)) return 1;

    // ---- Create TUN adapter ----
    WINTUN_ADAPTER_HANDLE adapter = pCreateAdapter(L"MyVPN", L"WireGuard", nullptr);
    if (!adapter)
    {
        std::cerr << "[ERROR] Failed to create Wintun adapter — run as Administrator\n";
        FreeLibrary(hWintun);
        return 1;
    }

    configureTunIp(adapter, assigned_ip);

    WINTUN_SESSION_HANDLE wintun_session = pStartSession(adapter, 0x400000);
    if (!wintun_session)
    {
        std::cerr << "[ERROR] Failed to start Wintun session\n";
        pCloseAdapter(adapter);
        FreeLibrary(hWintun);
        return 1;
    }

    std::cout << "[INFO] Wintun adapter ready\n";

    // ---- Event-driven loop setup ----
    HANDLE wintun_event = pGetReadWaitEvent(wintun_session);
    WSAEVENT udp_event  = WSACreateEvent();
    WSAEventSelect(sock, udp_event, FD_READ);

    HANDLE wait_handles[2] = { wintun_event, (HANDLE)udp_event };

    static uint8_t io_buf[2048];
    static uint8_t crypto_buf[2048];
    time_t last_keepalive = time(nullptr);

    std::cout << "[INFO] VPN running — Ctrl+C to disconnect\n";

    while (g_running)
    {
        // 30s timeout drives the keepalive
        DWORD wait = WaitForMultipleObjects(2, wait_handles, FALSE, 30000);

        // ---- TUN → UDP (Wintun has packets) ----
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
            }
        }

        // ---- UDP → TUN (server sent us data) ----
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

                int payload = n - (int)sizeof(PacketHeader);
                xorCrypt(io_buf + sizeof(PacketHeader), payload, crypto_buf, xor_key);

                BYTE *buf = pAllocateSendPacket(wintun_session, (DWORD)payload);
                if (buf)
                {
                    memcpy(buf, crypto_buf, payload);
                    pSendPacket(wintun_session, buf);
                }
            }
        }

        // ---- Keepalive every 30s ----
        time_t now = time(nullptr);
        if (now - last_keepalive >= 30)
        {
            PacketHeader ka{};
            ka.type       = PKT_KEEPALIVE;
            ka.session_id = htonl(session_id);
            sendto(sock, (char *)&ka, sizeof(ka), 0,
                   (sockaddr *)&server, sizeof(server));
            last_keepalive = now;
        }
    }

    // ---- Graceful disconnect ----
    PacketHeader bye{};
    bye.type       = PKT_BYE;
    bye.session_id = htonl(session_id);
    sendto(sock, (char *)&bye, sizeof(bye), 0, (sockaddr *)&server, sizeof(server));
    std::cout << "[INFO] Sent BYE to server\n";

    // ---- Cleanup ----
    WSACloseEvent(udp_event);
    pEndSession(wintun_session);
    pCloseAdapter(adapter);
    FreeLibrary(hWintun);
    closesocket(sock);
    WSACleanup();

    std::cout << "[INFO] Shutdown complete\n";
    return 0;
}
