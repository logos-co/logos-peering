#include "logos/peering/names.h"

#include <gtest/gtest.h>

using namespace logos::peering;

TEST(Names, ModuleNames)
{
    EXPECT_TRUE(isValidModuleName("monerod_module"));
    EXPECT_TRUE(isValidModuleName("Storage2"));
    EXPECT_FALSE(isValidModuleName(""));
    EXPECT_FALSE(isValidModuleName("2fast"));
    EXPECT_FALSE(isValidModuleName("@op:alice"));
    EXPECT_FALSE(isValidModuleName("bad-name"));
    EXPECT_FALSE(isValidModuleName("a\"b"));
}

TEST(Names, Aliases)
{
    EXPECT_TRUE(isValidAlias("office"));
    EXPECT_TRUE(isValidAlias("home-server_2"));
    EXPECT_FALSE(isValidAlias(""));
    EXPECT_FALSE(isValidAlias("Office"));
    EXPECT_FALSE(isValidAlias("-office"));
    EXPECT_FALSE(isValidAlias(std::string(64, 'a')));
}

TEST(Names, DisplayNames)
{
    EXPECT_TRUE(isValidDisplayName("Dario's laptop"));
    EXPECT_FALSE(isValidDisplayName(""));
    EXPECT_FALSE(isValidDisplayName("line\nbreak"));
    EXPECT_FALSE(isValidDisplayName(std::string(65, 'x')));
}
