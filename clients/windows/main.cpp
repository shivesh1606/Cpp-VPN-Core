#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "wintun.h"

#pragma comment(lib, "ws2_32.lib")

// ---------------- GLOBAL ----------------
volatile bool running = true;

BOOL WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT)
    {
        std::cout << "\nShutting down...\n";
        running = false;
    }
    return TRUE;
}

// ---------------- PACKETS ----------------
enum PacketType : uint8_t
{
    PKT_HELLO = 1,
    PKT_WELCOME = 2,
    PKT_CLIENT_ACK = 3,
    PKT_DATA = 4,
    PKT_BYE = 5
};

#pragma pack(push, 1)
struct PacketHeader
{
    uint8_t type;
    uint32_t session_id;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct HelloPacket
{
    PacketHeader hdr;
    uint32_t client_magic;
    uint32_t yc;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct WelcomePacket
{
    PacketHeader hdr;
    uint32_t assigned_tun_ip;
    uint32_t ys;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ClientAckPacket
{
    PacketHeader hdr;
};
#pragma pack(pop)

int main(int argc, char* argv[])
{
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " <server_ip> [port]\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int server_port = (argc >= 3) ? std::stoi(argv[2]) : 27015;

    // -------- Winsock --------
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &destAddr.sin_addr);

    // -------- HANDSHAKE --------
    uint32_t session_id = 0;

    HelloPacket hello_pkt{};
    hello_pkt.hdr.type = PKT_HELLO;
    hello_pkt.hdr.session_id = htonl(0);
    hello_pkt.client_magic = htonl(12345);
    hello_pkt.yc = htonl(67890);

    sendto(sock, (char*)&hello_pkt, sizeof(hello_pkt), 0,
           (sockaddr*)&destAddr, sizeof(destAddr));

    char buffer[2000];
    sockaddr_in fromAddr{};
    int fromLen = sizeof(fromAddr);

    int recvLen = recvfrom(sock, buffer, sizeof(buffer), 0,
                           (sockaddr*)&fromAddr, &fromLen);

    if (recvLen < sizeof(WelcomePacket))
    {
        std::cout << "Handshake failed\n";
        return 1;
    }

    WelcomePacket* welcome = (WelcomePacket*)buffer;
    session_id = ntohl(welcome->hdr.session_id);

    std::cout << "Handshake complete. Session: " << session_id << "\n";

    ClientAckPacket ack{};
    ack.hdr.type = PKT_CLIENT_ACK;
    ack.hdr.session_id = htonl(session_id);

    sendto(sock, (char*)&ack, sizeof(ack), 0,
           (sockaddr*)&destAddr, sizeof(destAddr));

    // -------- LOAD WINTUN --------
    HMODULE hWintun = LoadLibraryA("wintun.dll");
    if (!hWintun)
    {
        std::cout << "Failed to load wintun.dll\n";
        return 1;
    }

    // Function pointers
    auto WintunCreateAdapter = (WINTUN_ADAPTER_HANDLE(WINAPI*)(const WCHAR*, const WCHAR*, const GUID*))
        GetProcAddress(hWintun, "WintunCreateAdapter");

    auto WintunCloseAdapter = (void(WINAPI*)(WINTUN_ADAPTER_HANDLE))
        GetProcAddress(hWintun, "WintunCloseAdapter");

    auto WintunStartSession = (WINTUN_SESSION_HANDLE(WINAPI*)(WINTUN_ADAPTER_HANDLE, DWORD))
        GetProcAddress(hWintun, "WintunStartSession");

    auto WintunEndSession = (void(WINAPI*)(WINTUN_SESSION_HANDLE))
        GetProcAddress(hWintun, "WintunEndSession");

    auto WintunReceivePacket = (BYTE*(WINAPI*)(WINTUN_SESSION_HANDLE, DWORD*))
        GetProcAddress(hWintun, "WintunReceivePacket");

    auto WintunReleaseReceivePacket = (void(WINAPI*)(WINTUN_SESSION_HANDLE, BYTE*))
        GetProcAddress(hWintun, "WintunReleaseReceivePacket");

    auto WintunAllocateSendPacket = (BYTE*(WINAPI*)(WINTUN_SESSION_HANDLE, DWORD))
        GetProcAddress(hWintun, "WintunAllocateSendPacket");

    auto WintunSendPacket = (void(WINAPI*)(WINTUN_SESSION_HANDLE, BYTE*))
        GetProcAddress(hWintun, "WintunSendPacket");

    if (!WintunCreateAdapter || !WintunStartSession)
    {
        std::cout << "Failed to load Wintun functions\n";
        return 1;
    }

    // -------- CREATE ADAPTER --------
    WINTUN_ADAPTER_HANDLE adapter =
        WintunCreateAdapter(L"MyVPN", L"MyTunnel", NULL);

    if (!adapter)
    {
        std::cout << "Failed to create adapter\n";
        return 1;
    }

    WINTUN_SESSION_HANDLE session =
        WintunStartSession(adapter, 0x400000);

    if (!session)
    {
        std::cout << "Failed to start session\n";
        return 1;
    }

    std::cout << "Wintun ready ✅\n";

    // Non-blocking socket
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    // -------- MAIN LOOP --------
    while (running)
    {
        DWORD packetSize;
        BYTE* packet = WintunReceivePacket(session, &packetSize);

        if (packet)
        {
            std::vector<uint8_t> sendBuf(sizeof(PacketHeader) + packetSize);

            PacketHeader* hdr = (PacketHeader*)sendBuf.data();
            hdr->type = PKT_DATA;
            hdr->session_id = htonl(session_id);

            memcpy(sendBuf.data() + sizeof(PacketHeader),
                   packet, packetSize);

            sendto(sock,
                   (char*)sendBuf.data(),
                   sendBuf.size(),
                   0,
                   (sockaddr*)&destAddr,
                   sizeof(destAddr));

            WintunReleaseReceivePacket(session, packet);
        }

        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                           (sockaddr*)&fromAddr, &fromLen);

        if (len > sizeof(PacketHeader))
        {
            PacketHeader* hdr = (PacketHeader*)buffer;

            if (hdr->type == PKT_DATA)
            {
                int payloadSize = len - sizeof(PacketHeader);

                BYTE* buf = WintunAllocateSendPacket(session, payloadSize);
                memcpy(buf, buffer + sizeof(PacketHeader), payloadSize);
                WintunSendPacket(session, buf);
            }
        }

        Sleep(1);
    }

    // -------- CLEANUP --------
    std::cout << "Cleaning up...\n";

    WintunEndSession(session);
    WintunCloseAdapter(adapter);
    FreeLibrary(hWintun);

    closesocket(sock);
    WSACleanup();

    std::cout << "Shutdown complete ✅\n";
    return 0;
}