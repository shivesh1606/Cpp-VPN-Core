#include "auth/TagRegistry.h"

#include <cctype>
#include <sstream>

namespace auth
{

namespace
{
std::string trim(const std::string &s)
{
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        b++;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        e--;
    return s.substr(b, e - b);
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
} // namespace

bool TagRegistry::parse(const std::string &text, std::string &error)
{
    by_bit_.clear();
    by_name_.clear();
    std::istringstream in(text);
    std::string line;
    for (int no = 1; std::getline(in, line); no++)
    {
        const size_t hash = line.find('#');
        if (hash != std::string::npos)
            line.erase(hash);
        line = trim(line);
        if (line.empty())
            continue;
        auto fail = [&](const std::string &m) {
            error = "line " + std::to_string(no) + ": " + m;
            return false;
        };
        const size_t eq = line.find('=');
        if (eq == std::string::npos)
            return fail("expected 'bit = name'");
        const std::string bit_s = trim(line.substr(0, eq)), name = trim(line.substr(eq + 1));
        if (bit_s.empty() || bit_s.size() > 2 || bit_s.find_first_not_of("0123456789") != std::string::npos)
            return fail("bit must be 0..31, got '" + bit_s + "'");
        const int bit = std::stoi(bit_s);
        if (bit > 31)
            return fail("bit must be 0..31, got '" + bit_s + "'");
        if (!validName(name))
            return fail("invalid tag name '" + name + "'");
        if (by_bit_.count(bit))
            return fail("bit " + bit_s + " already used by '" + by_bit_[bit] + "'");
        if (by_name_.count(name))
            return fail("tag '" + name + "' already defined (bit " + std::to_string(by_name_[name]) + ")");
        by_bit_[bit] = name;
        by_name_[name] = bit;
    }
    return true;
}

bool TagRegistry::mask(const std::vector<std::string> &names, uint32_t &out, std::string &error) const
{
    if (names.empty())
    {
        error = "no tags given";
        return false;
    }
    uint32_t m = 0;
    for (const auto &n : names)
    {
        auto it = by_name_.find(n);
        if (it == by_name_.end())
        {
            error = "unknown tag '" + n + "' (not in tags.conf)";
            return false;
        }
        m |= uint32_t(1) << it->second;
    }
    out = m;
    return true;
}

std::string TagRegistry::names(uint32_t mask) const
{
    std::string s;
    for (int bit = 0; bit < 32; bit++)
    {
        if (!(mask & (uint32_t(1) << bit)))
            continue;
        auto it = by_bit_.find(bit);
        s += (s.empty() ? "" : ", ") + (it != by_bit_.end() ? it->second : "bit" + std::to_string(bit));
    }
    return s.empty() ? "(none)" : s;
}

} // namespace auth
