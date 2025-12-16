#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <cstdint>

/*
    Packet types exchanged over UDP BEFORE normal VPN data flow.
*/
enum PacketType : uint8_t
{
    PKT_HELLO = 1,      // Client → Server (handshake start)
    PKT_WELCOME = 2,    // Server → Client (IP + key assigned)
    PKT_CLIENT_ACK = 3, // Client → Server (ack welcome)
    PKT_DATA = 4,       // Encrypted VPN data
    PKT_BYE = 5         // Optional disconnect (best effort)
};

/*
    Common header for ALL packets.
    This allows you to inspect packet type
    BEFORE decrypting or routing.
*/
#pragma pack(push, 1)
struct PacketHeader
{
    uint8_t type;        // PacketType
    uint32_t session_id; // 0 during HELLO, non-zero after
};
#pragma pack(pop)

/*
    Client → Server
    First packet sent by client.
*/
#pragma pack(push, 1)
struct HelloPacket
{
    PacketHeader hdr;
    uint32_t client_magic; // random value (just for uniqueness)
};
#pragma pack(pop)

/*
    Server → Client
    Server assigns VPN IP + XOR key.
*/
#pragma pack(push, 1)
struct WelcomePacket
{
    PacketHeader hdr;
    uint32_t assigned_tun_ip; // server-assigned VPN IP (host order)
};
#pragma pack(pop)

/*
 Client → Server
 Client sends this to acknowledge WELCOME packet, with its own chosen XOR key.
*/
#pragma pack(push, 1)
struct ClientAckPacket
{
    PacketHeader hdr;
    char xor_key; // Simple XOR key chosen by client
};
#pragma pack(pop)
/*
    Encrypted VPN data packet.
    Payload is XOR-encrypted IPv4 packet.
*/
#pragma pack(push, 1)
struct DataPacket
{
    PacketHeader hdr;
    uint8_t payload[]; // encrypted data
};
#pragma pack(pop)

/*
Session state maintained per client after handshake.
*/
#pragma pack(push, 1)
struct SessionState
{
    sockaddr_in client_udp_addr;  // Client's real-world UDP address
    uint32_t client_magic;      // Echoed from HELLO
    uint32_t assigned_tun_ip; // server-assigned VPN IP (host order)
};
#pragma pack(pop)

#endif // HANDSHAKE_H
