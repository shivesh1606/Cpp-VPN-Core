// vpnctl - Phase 0 ticket issuer (design doc 03, sections 4-6, decisions T1-T4).
//
//   vpnctl init     [--key-id N] [--kdf interactive|moderate|sensitive]
//   vpnctl node add --id ID --host HOST [--port P] --pub S_PUB --tags a,b
//   vpnctl node list | node remove --id ID
//   vpnctl issue    --user NAME --tags a,b [--days N | --hours N] [--nodes id,id] [--tier T]
//   vpnctl revoke   --user NAME | --ticket ID
//   vpnctl users
//   vpnctl inspect  BUNDLE|FILE
//
// Global: --dir DIR (default $VPNCTL_DIR or ./vpnctl-data), --passphrase-file FILE
// (default $VPNCTL_PASSPHRASE, else a no-echo prompt on the terminal).
//
// Data directory (mode 0700):
//   issuer.key       issuer Ed25519 key, Argon2id + secretbox encrypted (0600). Back it up offline.
//   issuer.pub       "issuer_pk.N = ..." line for every node.conf
//   tags.conf        tag registry; copy to every node (auth.tags_file)
//   nodes.ini        nodes put into bundles
//   users.ini        user name -> random user_id (never an e-mail address) and issued tickets
//   revoked.ini      revoked users / tickets and the list sequence number
//   revocations.bin  signed revocation list: publish at revocation_url or copy to nodes
//   bundles/         issued bundles (cppvpn://import?b=...): SECRETS, they contain the device key
#include <sodium.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "auth/Bundle.h"
#include "auth/IssuerKey.h"
#include "auth/RevocationList.h"
#include "auth/TagRegistry.h"
#include "auth/Ticket.h"
#include "config/Ini.h"
#include "crypto/Base64Url.h"
#include "crypto/backends/SodiumAead.h"

namespace
{

struct Args
{
    std::vector<std::string> words; // positional (command, subcommand, inspect target)
    std::map<std::string, std::string> opts;
    bool has(const std::string &k) const { return opts.count(k) != 0; }
    std::string get(const std::string &k, const std::string &def = "") const
    {
        auto it = opts.find(k);
        return it == opts.end() ? def : it->second;
    }
};

std::string g_dir;

[[noreturn]] void die(const std::string &msg)
{
    std::fprintf(stderr, "vpnctl: %s\n", msg.c_str());
    std::exit(1);
}

std::string path(const std::string &name) { return g_dir + "/" + name; }

bool exists(const std::string &p)
{
    struct stat st{};
    return stat(p.c_str(), &st) == 0;
}

std::string readFile(const std::string &p)
{
    std::string text, err;
    if (!config::readTextFile(p, text, err))
        die(err);
    return text;
}

// Writes atomically (tmp + rename) with `mode`.
void writeFile(const std::string &p, const std::string &content, mode_t mode = 0644)
{
    const std::string tmp = p + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f || !(f << content) || !f.flush())
            die("cannot write " + tmp);
    }
    chmod(tmp.c_str(), mode);
    if (std::rename(tmp.c_str(), p.c_str()) != 0)
        die("cannot rename " + tmp + ": " + std::strerror(errno));
}

std::string hexOf(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
        s += {d[p[i] >> 4], d[p[i] & 15]};
    return s;
}

bool fromHex(const std::string &s, uint8_t *out, size_t n)
{
    if (s.size() != 2 * n)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        unsigned v = 0;
        if (std::sscanf(s.c_str() + 2 * i, "%2x", &v) != 1)
            return false;
        out[i] = uint8_t(v);
    }
    return s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

std::string ticketIdHex(uint64_t id)
{
    char b[17];
    std::snprintf(b, sizeof(b), "%016llx", (unsigned long long)id);
    return b;
}

std::string utc(uint64_t t)
{
    const time_t tt = time_t(t);
    char b[32];
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M UTC", std::gmtime(&tt));
    return b;
}

bool validName(const std::string &s)
{
    if (s.empty() || s.size() > 32)
        return false;
    for (char c : s)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.')
            return false;
    return true;
}

config::IniFile readIni(const std::string &name)
{
    config::IniFile ini;
    if (!exists(path(name)))
        return ini;
    std::string err;
    if (!ini.parse(readFile(path(name)), err))
        die(path(name) + ": " + err);
    return ini;
}

std::string iniValue(const config::IniFile &ini, const std::string &sec, const std::string &key)
{
    const config::IniEntry *e = ini.get(sec, key);
    return e ? e->value : "";
}

// Serializes an IniFile back to text, grouped by section in first-seen order.
std::string iniText(const config::IniFile &ini, const std::string &header)
{
    std::vector<std::string> sections;
    for (const auto &sk : ini.keys())
        if (std::find(sections.begin(), sections.end(), sk.first) == sections.end())
            sections.push_back(sk.first);
    std::string out = header;
    for (const auto &sec : sections)
    {
        out += "\n[" + sec + "]\n";
        for (const auto &sk : ini.keys())
            if (sk.first == sec)
                out += sk.second + " = " + ini.get(sec, sk.second)->value + "\n";
    }
    return out;
}

// ---------------- passphrase ----------------

std::string readPassphrase(const Args &a, bool confirm)
{
    if (a.has("--passphrase-file"))
    {
        std::string p = readFile(a.get("--passphrase-file"));
        while (!p.empty() && (p.back() == '\n' || p.back() == '\r'))
            p.pop_back();
        return p;
    }
    if (const char *env = std::getenv("VPNCTL_PASSPHRASE"))
        return env;
    FILE *tty = std::fopen("/dev/tty", "r+");
    if (!tty)
        die("no terminal for the passphrase prompt; set VPNCTL_PASSPHRASE or use --passphrase-file");
    auto ask = [&](const char *prompt) {
        std::fprintf(tty, "%s", prompt);
        std::fflush(tty);
        termios old{}, quiet{};
        tcgetattr(fileno(tty), &old);
        quiet = old;
        quiet.c_lflag &= ~tcflag_t(ECHO);
        tcsetattr(fileno(tty), TCSAFLUSH, &quiet);
        char buf[512] = {0};
        const bool got = std::fgets(buf, sizeof(buf), tty) != nullptr;
        tcsetattr(fileno(tty), TCSAFLUSH, &old);
        std::fprintf(tty, "\n");
        std::string s = got ? buf : "";
        sodium_memzero(buf, sizeof(buf));
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        return s;
    };
    std::string p = ask("Issuer key passphrase: ");
    if (confirm && ask("Repeat passphrase: ") != p)
    {
        std::fclose(tty);
        die("passphrases differ");
    }
    std::fclose(tty);
    return p;
}

void loadIssuer(const Args &a, auth::IssuerKey &key)
{
    if (!exists(path("issuer.key")))
        die("no issuer key in " + g_dir + " (run: vpnctl init)");
    std::string pass = readPassphrase(a, false), err;
    if (!auth::loadIssuerKey(path("issuer.key"), pass, key, err))
        die(err);
    sodium_memzero(&pass[0], pass.size());
}

auth::TagRegistry loadTags()
{
    auth::TagRegistry r;
    std::string err;
    if (!r.parse(readFile(path("tags.conf")), err))
        die(path("tags.conf") + ": " + err);
    return r;
}

uint32_t tagMask(const auth::TagRegistry &r, const std::string &list)
{
    uint32_t m = 0;
    std::string err;
    if (!r.mask(config::splitList(list), m, err))
        die(err);
    return m;
}

// ---------------- commands ----------------

int cmdInit(const Args &a)
{
    if (exists(path("issuer.key")))
        die(path("issuer.key") + " already exists. An issuer key is never overwritten: every ticket and "
                                 "every node depends on it (rotation: design 03 section 4).");
    mkdir(g_dir.c_str(), 0700);
    chmod(g_dir.c_str(), 0700);
    mkdir(path("bundles").c_str(), 0700);
    const int key_id = std::atoi(a.get("--key-id", "1").c_str());
    if (key_id < 1 || key_id > 255)
        die("--key-id must be 1..255");
    const std::string kdf = a.get("--kdf", "moderate");
    const auth::KdfStrength strength = kdf == "interactive" ? auth::KdfStrength::kInteractive
                                       : kdf == "sensitive" ? auth::KdfStrength::kSensitive
                                                            : auth::KdfStrength::kModerate;
    std::string pass = readPassphrase(a, true), err;
    if (pass.size() < 12)
        die("use a passphrase of at least 12 characters");
    auth::IssuerKey key;
    if (!auth::generateIssuerKey(uint8_t(key_id), key) || !auth::saveIssuerKey(path("issuer.key"), key, pass, strength, err))
        die(err.empty() ? "key generation failed" : err);
    sodium_memzero(&pass[0], pass.size());
    const std::string pub_line = "issuer_pk." + std::to_string(key_id) + " = " + crypto::toBase64Url(key.pk, 32);
    writeFile(path("issuer.pub"), pub_line + "\n");
    if (!exists(path("tags.conf")))
        writeFile(path("tags.conf"), "# bit = name  (design 03 section 3). Shared with every node (auth.tags_file).\n"
                                     "# Bits are never reused: removing a tag means retiring its bit.\n"
                                     "0 = friends\n1 = free\n2 = premium\n8 = region-in\n9 = region-us\n");
    std::printf("Issuer key %d created in %s (encrypted, %s key derivation).\n", key_id, g_dir.c_str(), kdf.c_str());
    std::printf("Back up %s offline: losing it means re-issuing every ticket.\n\n", path("issuer.key").c_str());
    std::printf("Add to every node's /etc/cppvpn/node.conf, section [auth]:\n  mode = ticket\n  %s\n", pub_line.c_str());
    std::printf("and copy %s to the node's /etc/cppvpn/tags.conf.\n", path("tags.conf").c_str());
    return 0;
}

int cmdNode(const Args &a)
{
    const std::string sub = a.words.size() > 1 ? a.words[1] : "";
    config::IniFile nodes = readIni("nodes.ini");
    if (sub == "add")
    {
        const std::string id = a.get("--id"), host = a.get("--host"), pub = a.get("--pub"), tags = a.get("--tags");
        const int port = std::atoi(a.get("--port", "5555").c_str());
        uint8_t pk[32];
        if (!validName(id))
            die("--id: 1-32 characters [A-Za-z0-9_.-]");
        if (host.empty() || host.size() > 253 || host.find_first_of(" \t/") != std::string::npos)
            die("--host: IPv4 address or DNS name of the node");
        if (port < 1 || port > 65535)
            die("--port: 1..65535");
        if (!crypto::fromBase64Url(pub, pk, 32))
            die("--pub: the node's public key (on the node: vpn_server --pubkey /etc/cppvpn/node.key)");
        tagMask(loadTags(), tags); // validates the names
        const std::string sec = "node." + id;
        nodes.set(sec, "host", host);
        nodes.set(sec, "port", std::to_string(port));
        nodes.set(sec, "pub", pub);
        nodes.set(sec, "tags", tags);
        writeFile(path("nodes.ini"), iniText(nodes, "# vpnctl nodes: written by 'vpnctl node add'\n"));
        std::printf("node %s: %s:%d tags %s\n", id.c_str(), host.c_str(), port, tags.c_str());
        return 0;
    }
    if (sub == "remove")
    {
        config::IniFile kept;
        bool found = false;
        for (const auto &sk : nodes.keys())
        {
            if (sk.first == "node." + a.get("--id"))
                found = true;
            else
                kept.set(sk.first, sk.second, nodes.get(sk.first, sk.second)->value);
        }
        if (!found)
            die("no node " + a.get("--id"));
        writeFile(path("nodes.ini"), iniText(kept, "# vpnctl nodes: written by 'vpnctl node add'\n"));
        return 0;
    }
    if (sub == "list")
    {
        for (const auto &sk : nodes.keys())
            if (sk.second == "host")
                std::printf("%-16s %s:%s  tags %s\n", sk.first.substr(5).c_str(), iniValue(nodes, sk.first, "host").c_str(),
                            iniValue(nodes, sk.first, "port").c_str(), iniValue(nodes, sk.first, "tags").c_str());
        return 0;
    }
    die("usage: vpnctl node add|list|remove ...");
}

int cmdIssue(const Args &a)
{
    const std::string user = a.get("--user"), tags = a.get("--tags");
    if (!validName(user))
        die("--user: a short name, 1-32 characters [A-Za-z0-9_.-] (it never leaves this directory)");
    const auth::TagRegistry reg = loadTags();
    const uint32_t mask = tagMask(reg, tags);
    long hours = a.has("--hours") ? std::atol(a.get("--hours").c_str()) : 24 * std::atol(a.get("--days", "30").c_str());
    if (hours < 1 || hours > 24 * 3650)
        die("--days / --hours: lifetime from 1 hour to 10 years");
    const int tier = std::atoi(a.get("--tier", "0").c_str());
    if (tier < 0 || tier > 255)
        die("--tier: 0..255");

    // Nodes: those named with --nodes, else every node whose tags intersect the ticket's.
    const config::IniFile nodes = readIni("nodes.ini");
    const std::vector<std::string> wanted = config::splitList(a.get("--nodes"));
    auth::Bundle b;
    for (const auto &sk : nodes.keys())
    {
        if (sk.second != "host")
            continue;
        auth::BundleNode n;
        n.id = sk.first.substr(5);
        n.host = iniValue(nodes, sk.first, "host");
        n.port = uint16_t(std::atoi(iniValue(nodes, sk.first, "port").c_str()));
        if (!crypto::fromBase64Url(iniValue(nodes, sk.first, "pub"), n.pub, 32))
            die("nodes.ini: bad pub for " + n.id);
        n.tags = tagMask(reg, iniValue(nodes, sk.first, "tags"));
        const bool named = std::find(wanted.begin(), wanted.end(), n.id) != wanted.end();
        if (wanted.empty() ? (n.tags & mask) != 0 : named)
            b.nodes.push_back(n);
    }
    for (const auto &w : wanted)
        if (std::none_of(b.nodes.begin(), b.nodes.end(), [&](const auto &n) { return n.id == w; }))
            die("--nodes: unknown node '" + w + "' (vpnctl node list)");
    if (b.nodes.empty())
        die("no node carries any of the tags '" + tags + "' (vpnctl node add ... --tags, or --nodes)");
    if (b.nodes.size() > auth::kMaxBundleNodes)
        die("too many nodes for one bundle");

    auth::IssuerKey issuer;
    loadIssuer(a, issuer);

    // User id: random 128 bits, stable per user name (design 03: never an e-mail address).
    config::IniFile users = readIni("users.ini");
    const std::string usec = "user." + user;
    uint8_t user_id[16];
    if (!fromHex(iniValue(users, usec, "user_id"), user_id, 16))
    {
        randombytes_buf(user_id, 16);
        users.set(usec, "user_id", hexOf(user_id, 16));
    }

    // Device key pair generated here (decision T1): its private half goes into the bundle.
    auth::Ticket t;
    randombytes_buf(b.device_sk, 32);
    crypto_scalarmult_base(t.device_pk, b.device_sk);
    t.key_id = issuer.key_id;
    t.tier = uint8_t(tier);
    std::memcpy(t.user_id, user_id, 16);
    t.tags = mask;
    const uint64_t now = uint64_t(std::time(nullptr));
    t.nbf = uint32_t(now);
    t.exp = uint32_t(now + uint64_t(hours) * 3600);
    do
        randombytes_buf(&t.ticket_id, sizeof(t.ticket_id));
    while (t.ticket_id == 0);
    if (!auth::sign(t, issuer.sk))
        die("signing failed");
    b.ticket.resize(auth::kTicketLen);
    auth::encode(t, b.ticket.data());

    const std::string uri = auth::bundleToUri(b);
    const std::string tid = ticketIdHex(t.ticket_id);
    users.set(usec, "ticket." + tid, std::to_string(t.exp) + " " + tags);
    writeFile(path("users.ini"), iniText(users, "# vpnctl users: name -> random user_id, issued tickets (exp tags)\n"), 0600);
    mkdir(path("bundles").c_str(), 0700);
    const std::string bundle_file = path("bundles/" + user + "-" + tid + ".txt");
    writeFile(bundle_file, uri + "\n", 0600);

    std::fprintf(stderr, "Ticket %s for %s: tags %s, valid until %s, %zu node(s):", tid.c_str(), user.c_str(),
                 reg.names(mask).c_str(), utc(t.exp).c_str(), b.nodes.size());
    for (const auto &n : b.nodes)
        std::fprintf(stderr, " %s", n.id.c_str());
    std::fprintf(stderr, "\nBundle saved to %s (mode 0600).\n"
                         "SECRET: it contains the device key. Share it only over a private channel.\n"
                         "QR code: qrencode -t ansiutf8 < %s\n", bundle_file.c_str(), bundle_file.c_str());
    std::printf("%s\n", uri.c_str());
    return 0;
}

int cmdRevoke(const Args &a)
{
    config::IniFile revoked = readIni("revoked.ini");
    const config::IniFile users = readIni("users.ini");
    if (a.has("--user"))
    {
        const std::string user = a.get("--user");
        uint8_t uid[16];
        if (!fromHex(iniValue(users, "user." + user, "user_id"), uid, 16))
            die("no user '" + user + "' (vpnctl users)");
        revoked.set("users", user, hexOf(uid, 16));
    }
    else if (a.has("--ticket"))
    {
        std::string id = a.get("--ticket");
        if (id.rfind("0x", 0) == 0)
            id.erase(0, 2);
        uint8_t raw[8];
        if (id.size() != 16 || !fromHex(id, raw, 8))
            die("--ticket: the 16-hex-digit ticket id (vpnctl users)");
        revoked.set("tickets", id, "revoked");
    }
    else
        die("usage: vpnctl revoke --user NAME | --ticket ID");

    auth::IssuerKey issuer;
    loadIssuer(a, issuer);
    auth::RevocationList l;
    l.key_id = issuer.key_id;
    l.seq = std::strtoull(iniValue(revoked, "state", "seq").c_str(), nullptr, 10) + 1;
    l.issued_at = uint32_t(std::time(nullptr));
    for (const auto &sk : revoked.keys())
    {
        const std::string v = revoked.get(sk.first, sk.second)->value;
        uint8_t uid[16];
        if (sk.first == "users" && fromHex(v, uid, 16))
            l.addUser(uid);
        else if (sk.first == "tickets")
            l.addTicket(std::strtoull(sk.second.c_str(), nullptr, 16));
    }
    revoked.set("state", "seq", std::to_string(l.seq));
    const std::vector<uint8_t> bytes = l.encodeSigned(issuer.sk);
    writeFile(path("revocations.bin"), std::string(bytes.begin(), bytes.end()));
    writeFile(path("revoked.ini"), iniText(revoked, "# vpnctl revocations (the signed list is revocations.bin)\n"));
    std::printf("Revocation list seq %llu: %zu entr%s, written to %s\n", (unsigned long long)l.seq, l.size(),
                l.size() == 1 ? "y" : "ies", path("revocations.bin").c_str());
    std::printf("Publish it: commit/push it to the file behind the nodes' revocation_url, or copy it to each\n"
                "node's revocation_file (/etc/cppvpn/revocations.bin); nodes reload it within a second.\n");
    return 0;
}

int cmdUsers(const Args &)
{
    const config::IniFile users = readIni("users.ini"), revoked = readIni("revoked.ini");
    const uint64_t now = uint64_t(std::time(nullptr));
    for (const auto &sk : users.keys())
    {
        if (sk.second == "user_id")
        {
            const std::string name = sk.first.substr(5);
            std::printf("%s  user_id %s%s\n", name.c_str(), users.get(sk.first, sk.second)->value.c_str(),
                        revoked.get("users", name) ? "  REVOKED" : "");
        }
        else if (sk.second.rfind("ticket.", 0) == 0)
        {
            const std::string id = sk.second.substr(7), v = users.get(sk.first, sk.second)->value;
            const uint64_t exp = std::strtoull(v.c_str(), nullptr, 10);
            std::printf("    ticket %s  tags %-20s  until %s%s\n", id.c_str(),
                        v.substr(v.find(' ') == std::string::npos ? v.size() : v.find(' ') + 1).c_str(),
                        utc(exp).c_str(), revoked.get("tickets", id) ? "  REVOKED" : exp <= now ? "  expired" : "");
        }
    }
    return 0;
}

int cmdInspect(const Args &a)
{
    if (a.words.size() < 2)
        die("usage: vpnctl inspect BUNDLE|FILE");
    std::string text = a.words[1];
    if (exists(text))
        text = readFile(text);
    auth::Bundle b;
    std::string err;
    if (!auth::bundleFromText(text, b, err))
        die(err);
    auth::Ticket t;
    if (!auth::decode(b.ticket.data(), b.ticket.size(), t))
        die("bundle has a malformed ticket");
    uint8_t pk[32];
    crypto_scalarmult_base(pk, b.device_sk);
    auth::TagRegistry reg;
    const bool have_tags = exists(path("tags.conf")) && reg.parse(readFile(path("tags.conf")), err);
    std::printf("bundle: %zu node(s)\n", b.nodes.size());
    for (const auto &n : b.nodes)
        std::printf("  %-16s %s:%u  S_pub %s  tags %s\n", n.id.c_str(), n.host.c_str(), n.port,
                    crypto::toBase64Url(n.pub, 32).c_str(), have_tags ? reg.names(n.tags).c_str() : ticketIdHex(n.tags).c_str());
    std::printf("ticket %s: key_id %u tier %u user_id %s\n  tags %s, valid %s .. %s\n  device key %s (%s the bundle's device key)\n",
                ticketIdHex(t.ticket_id).c_str(), t.key_id, t.tier, hexOf(t.user_id, 16).c_str(),
                have_tags ? reg.names(t.tags).c_str() : ticketIdHex(t.tags).c_str(), utc(t.nbf).c_str(), utc(t.exp).c_str(),
                crypto::toBase64Url(t.device_pk, 32).c_str(),
                crypto_verify_32(pk, t.device_pk) == 0 ? "matches" : "DOES NOT MATCH");
    if (exists(path("issuer.pub")))
    {
        const std::string line = readFile(path("issuer.pub"));
        const size_t eq = line.find('=');
        auth::PublicKey ipk;
        std::string b64 = eq == std::string::npos ? "" : line.substr(eq + 1);
        b64.erase(0, b64.find_first_not_of(" \t"));
        b64.erase(b64.find_last_not_of(" \t\r\n") + 1);
        if (crypto::fromBase64Url(b64, ipk.data(), 32))
        {
            const auth::IssuerKeys keys{{t.key_id, ipk}};
            const auth::Verdict v = auth::verify(b.ticket.data(), b.ticket.size(), t.device_pk, uint64_t(std::time(nullptr)),
                                                 keys, ~uint32_t(0), nullptr);
            std::printf("  check against %s: %s\n", path("issuer.pub").c_str(), auth::verdictName(v));
        }
    }
    return 0;
}

int usage()
{
    std::fprintf(stderr,
                 "usage: vpnctl [--dir DIR] [--passphrase-file FILE] COMMAND\n"
                 "  init     [--key-id N] [--kdf interactive|moderate|sensitive]\n"
                 "  node add --id ID --host HOST [--port P] --pub S_PUB --tags a,b\n"
                 "  node list | node remove --id ID\n"
                 "  issue    --user NAME --tags a,b [--days N | --hours N] [--nodes id,...] [--tier T]\n"
                 "  revoke   --user NAME | --ticket ID\n"
                 "  users\n"
                 "  inspect  BUNDLE|FILE\n"
                 "Data directory: --dir, else $VPNCTL_DIR, else ./vpnctl-data. Passphrase: --passphrase-file,\n"
                 "else $VPNCTL_PASSPHRASE, else prompted. See docs/design/03-tickets.md section 5.\n");
    return 2;
}

} // namespace

int main(int argc, char **argv)
{
    if (!crypto::sodiumReady())
        die("libsodium init failed");
    Args a;
    for (int i = 1; i < argc; i++)
    {
        const std::string s = argv[i];
        if (s.rfind("--", 0) == 0)
        {
            if (s == "--help")
                return usage();
            if (i + 1 >= argc)
                die(s + " needs a value");
            a.opts[s] = argv[++i];
        }
        else
            a.words.push_back(s);
    }
    if (a.words.empty())
        return usage();
    const char *env_dir = std::getenv("VPNCTL_DIR");
    g_dir = a.get("--dir", env_dir ? env_dir : "vpnctl-data");
    const std::string cmd = a.words[0];
    if (cmd == "init") return cmdInit(a);
    if (cmd == "node") return cmdNode(a);
    if (cmd == "issue") return cmdIssue(a);
    if (cmd == "revoke") return cmdRevoke(a);
    if (cmd == "users") return cmdUsers(a);
    if (cmd == "inspect") return cmdInspect(a);
    return usage();
}
