#include "config/Ini.h"

#include <cctype>
#include <fstream>
#include <sstream>

namespace config
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
    if (s.empty())
        return false;
    for (char c : s)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.')
            return false;
    return true;
}

// Removes an inline comment: ';' or '#' preceded by whitespace.
std::string stripInlineComment(const std::string &s)
{
    for (size_t i = 1; i < s.size(); i++)
        if ((s[i] == ';' || s[i] == '#') && std::isspace(static_cast<unsigned char>(s[i - 1])))
            return s.substr(0, i);
    return s;
}

} // namespace

bool IniFile::parse(const std::string &text, std::string &error)
{
    std::string body = text;
    if (body.compare(0, 3, "\xEF\xBB\xBF") == 0)
        body.erase(0, 3); // UTF-8 BOM

    std::istringstream in(body);
    std::string raw, section;
    int line_no = 0;
    while (std::getline(in, raw))
    {
        line_no++;
        if (!raw.empty() && raw.back() == '\r')
            raw.pop_back();
        std::string line = trim(raw);
        if (line.empty() || line[0] == ';' || line[0] == '#')
            continue;
        line = trim(stripInlineComment(line));

        auto fail = [&](const std::string &msg) {
            error = "line " + std::to_string(line_no) + ": " + msg;
            return false;
        };

        if (line[0] == '[')
        {
            if (line.back() != ']')
                return fail("section header must end with ']'");
            section = trim(line.substr(1, line.size() - 2));
            if (!validName(section))
                return fail("invalid section name '" + section + "'");
            continue;
        }

        const size_t eq = line.find('=');
        if (eq == std::string::npos)
            return fail("expected 'key = value'");
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));
        if (!validName(key))
            return fail("invalid key name '" + key + "'");
        if (section.empty())
            return fail("key '" + key + "' is outside any [section]");
        if (get(section, key))
            return fail("duplicate key '" + key + "' in [" + section + "] (first on line " +
                        std::to_string(get(section, key)->line) + ")");
        data_[section][key] = IniEntry{value, line_no};
        order_.emplace_back(section, key);
    }
    return true;
}

void IniFile::set(const std::string &section, const std::string &key, const std::string &value)
{
    if (!get(section, key))
        order_.emplace_back(section, key);
    data_[section][key] = IniEntry{value, 0};
}

const IniEntry *IniFile::get(const std::string &section, const std::string &key) const
{
    auto s = data_.find(section);
    if (s == data_.end())
        return nullptr;
    auto k = s->second.find(key);
    return k == s->second.end() ? nullptr : &k->second;
}

bool readTextFile(const std::string &path, std::string &out, std::string &error)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        error = "cannot open " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

std::vector<std::string> splitList(const std::string &value)
{
    std::vector<std::string> out;
    std::string item;
    std::istringstream in(value);
    while (std::getline(in, item, ','))
    {
        item = trim(item);
        if (!item.empty())
            out.push_back(item);
    }
    return out;
}

} // namespace config
