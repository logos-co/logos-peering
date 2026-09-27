#include "logos/peering/callers.h"

#include <gtest/gtest.h>

using namespace logos::peering;

TEST(Callers, StrictParseRefusesDuplicateKeysAtAnyDepth)
{
    EXPECT_TRUE(parseStrictObject(R"({"kind":"module","name":"x"})").has_value());
    EXPECT_FALSE(parseStrictObject(R"({"kind":"module","kind":"host"})").has_value());
    EXPECT_FALSE(parseStrictObject(R"({"a":{"b":1,"b":2}})").has_value());
    EXPECT_TRUE(parseStrictObject(R"({"a":{"b":1},"c":{"b":2}})").has_value());
    EXPECT_FALSE(parseStrictObject("[1,2]").has_value());
    EXPECT_FALSE(parseStrictObject("{").has_value());
}

TEST(Callers, ConsumerMappingFollowsTheCallerKind)
{
    EXPECT_EQ(consumerForCallerJson(R"({"kind":"module","name":"monerod_ui"})"), "monerod_ui");
    EXPECT_EQ(consumerForCallerJson(R"({"kind":"host"})"), "runtime");
    EXPECT_EQ(consumerForCallerJson(R"({"kind":"operator","name":"alice"})"), "@op:alice");
    EXPECT_FALSE(consumerForCallerJson(R"({"kind":"unknown"})").has_value());
    EXPECT_FALSE(consumerForCallerJson(R"({"kind":"derived","name":"x"})").has_value());
    EXPECT_FALSE(consumerForCallerJson(R"({"kind":"module","name":"@runtime"})").has_value());
    EXPECT_FALSE(consumerForCallerJson(R"({"kind":"module","name":"x","kind":"host"})").has_value());
}

TEST(Callers, ConsumersThatMayTravel)
{
    EXPECT_TRUE(isValidConsumer("runtime"));
    EXPECT_TRUE(isValidConsumer("wallet"));
    EXPECT_TRUE(isValidConsumer("@op:alice"));
    EXPECT_FALSE(isValidConsumer("@op:"));
    EXPECT_FALSE(isValidConsumer("@runtime"));
    EXPECT_FALSE(isValidConsumer("core\"x"));
}

TEST(Callers, RemotePrincipals)
{
    const auto p = remotePrincipal("11111111-1111-4111-8111-111111111111", "wallet");
    EXPECT_EQ(p["kind"], "remote");
    EXPECT_EQ(p["peer"], "11111111-1111-4111-8111-111111111111");
    EXPECT_EQ(p["name"], "wallet");
}
