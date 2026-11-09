// Ini.h - Minimal INI reader for node.conf (plan Discussion 4a, decision N2).
//
// Syntax:
//   [section]                 names: letters, digits, '_', '-', '.'
//   key = value               value is trimmed; may be empty
//   ; comment  or  # comment  whole-line comments
//   key = value   ; comment   inline comments need whitespace before ';' or '#',
//                             so "https://host/x#frag" stays intact
// Every key must be inside a section. A key repeated within one section is an error
// (it is almost always a copy-paste mistake). A UTF-8 BOM and CRLF line endings are accepted.
#ifndef CONFIG_INI_H
#define CONFIG_INI_H

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace config
{

struct IniEntry
{
    std::string value;
    int line = 0; // 1-based line in the source; 0 for values set programmatically
};

class IniFile
{
public:
    // Parses `text`. On a syntax error returns false and sets `error` to "line N: ...".
    bool parse(const std::string &text, std::string &error);

    // Sets or replaces a value (used for command-line --set overrides).
    void set(const std::string &section, const std::string &key, const std::string &value);

    const IniEntry *get(const std::string &section, const std::string &key) const;

    // (section, key) pairs in first-seen order.
    const std::vector<std::pair<std::string, std::string>> &keys() const { return order_; }

private:
    std::map<std::string, std::map<std::string, IniEntry>> data_;
    std::vector<std::pair<std::string, std::string>> order_;
};

// Reads a whole file. Returns false and sets `error` if it cannot be read.
bool readTextFile(const std::string &path, std::string &out, std::string &error);

// "a, b ,c" -> {"a", "b", "c"}; empty items are dropped.
std::vector<std::string> splitList(const std::string &value);

} // namespace config

#endif // CONFIG_INI_H
