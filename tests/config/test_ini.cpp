// IniFile: node.conf syntax (plan N2).
#include <gtest/gtest.h>

#include "config/Ini.h"

using config::IniFile;

namespace
{
IniFile parseOk(const std::string &text)
{
    IniFile ini;
    std::string err;
    EXPECT_TRUE(ini.parse(text, err)) << err;
    return ini;
}

std::string parseError(const std::string &text)
{
    IniFile ini;
    std::string err;
    EXPECT_FALSE(ini.parse(text, err));
    return err;
}
} // namespace

TEST(Ini, SectionsKeysAndTrimming)
{
    const IniFile ini = parseOk("[node]\n  port   =   5555  \nid=in-1\n[tunnel]\ntun_name = tun0\n");
    ASSERT_NE(ini.get("node", "port"), nullptr);
    EXPECT_EQ(ini.get("node", "port")->value, "5555");
    EXPECT_EQ(ini.get("node", "port")->line, 2);
    EXPECT_EQ(ini.get("node", "id")->value, "in-1");
    EXPECT_EQ(ini.get("tunnel", "tun_name")->value, "tun0");
    EXPECT_EQ(ini.get("tunnel", "port"), nullptr);
    EXPECT_EQ(ini.keys().size(), 3u);
    EXPECT_EQ(ini.keys()[2], std::make_pair(std::string("tunnel"), std::string("tun_name")));
}

TEST(Ini, CommentsWholeLineAndInline)
{
    const IniFile ini = parseOk("; header comment\n# another\n[node]\n"
                                "tags = friends, region-in   ; design 03\n"
                                "port = 5555 # inline hash\n");
    EXPECT_EQ(ini.get("node", "tags")->value, "friends, region-in");
    EXPECT_EQ(ini.get("node", "port")->value, "5555");
}

TEST(Ini, HashOrSemicolonWithoutLeadingSpaceIsPartOfValue)
{
    const IniFile ini = parseOk("[auth]\nrevocation_url = https://h/x#frag;v=1\n");
    EXPECT_EQ(ini.get("auth", "revocation_url")->value, "https://h/x#frag;v=1");
}

TEST(Ini, EmptyValueAndDottedKeys)
{
    const IniFile ini = parseOk("[crypto]\nimpl.aes256gcm = openssl\nempty =\n");
    EXPECT_EQ(ini.get("crypto", "impl.aes256gcm")->value, "openssl");
    EXPECT_EQ(ini.get("crypto", "empty")->value, "");
}

TEST(Ini, AcceptsCrlfAndUtf8Bom)
{
    const IniFile ini = parseOk("\xEF\xBB\xBF[node]\r\nport = 6000\r\n");
    EXPECT_EQ(ini.get("node", "port")->value, "6000");
}

TEST(Ini, ErrorsNameTheLine)
{
    EXPECT_EQ(parseError("[node]\nport 5555\n"), "line 2: expected 'key = value'");
    EXPECT_EQ(parseError("port = 1\n"), "line 1: key 'port' is outside any [section]");
    EXPECT_EQ(parseError("[node\n"), "line 1: section header must end with ']'");
    EXPECT_EQ(parseError("[no de]\n"), "line 1: invalid section name 'no de'");
    EXPECT_EQ(parseError("[node]\nbad key = 1\n"), "line 2: invalid key name 'bad key'");
}

TEST(Ini, DuplicateKeyInSectionIsAnError)
{
    EXPECT_EQ(parseError("[node]\nport = 1\n\nport = 2\n"),
              "line 4: duplicate key 'port' in [node] (first on line 2)");
    // Same key in different sections is fine; a repeated section header continues it.
    parseOk("[a]\nk = 1\n[b]\nk = 2\n[a]\nother = 3\n");
}

TEST(Ini, SetOverridesAndMarksLineZero)
{
    IniFile ini = parseOk("[node]\nport = 5555\n");
    ini.set("node", "port", "6000");
    ini.set("tunnel", "mtu", "1400");
    EXPECT_EQ(ini.get("node", "port")->value, "6000");
    EXPECT_EQ(ini.get("node", "port")->line, 0);
    EXPECT_EQ(ini.get("tunnel", "mtu")->value, "1400");
    EXPECT_EQ(ini.keys().size(), 2u); // replaced key is not listed twice
}

TEST(Ini, SplitList)
{
    EXPECT_EQ(config::splitList(" a, b ,,c "), (std::vector<std::string>{"a", "b", "c"}));
    EXPECT_TRUE(config::splitList("  ").empty());
}
