// TagRegistry.h - tags.conf: tag names <-> ticket scope bits (design doc 03, section 3, T2).
// Portable. Shared by vpnctl (issuing: names -> ticket.tags) and nodes (node.tags -> node_mask).
//
//   # bit = name   (bits are never reused)
//   0 = friends
//   8 = region-in
#ifndef AUTH_TAGREGISTRY_H
#define AUTH_TAGREGISTRY_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace auth
{

class TagRegistry
{
public:
    // Parses tags.conf text. Errors name the line ("line 3: ...").
    bool parse(const std::string &text, std::string &error);
    // Mask for a list of tag names; false (and `error`) for an unknown name or an empty list.
    bool mask(const std::vector<std::string> &names, uint32_t &out, std::string &error) const;
    // "friends, region-in" for a mask (unknown bits as "bit7").
    std::string names(uint32_t mask) const;
    const std::map<int, std::string> &byBit() const { return by_bit_; }

private:
    std::map<int, std::string> by_bit_;
    std::map<std::string, int> by_name_;
};

} // namespace auth

#endif // AUTH_TAGREGISTRY_H
