#include "logos/peering/discovery_key.h"

#include <gtest/gtest.h>

#include <regex>

using namespace logos::peering;
using namespace std::chrono_literals;

TEST(DiscoveryKey, EpochsAreFifteenMinutes)
{
    const auto t0 = std::chrono::system_clock::time_point(900s * 1000);
    EXPECT_EQ(discoveryEpoch(t0), 1000u);
    EXPECT_EQ(discoveryEpoch(t0 + 899s), 1000u);
    EXPECT_EQ(discoveryEpoch(t0 + 900s), 1001u);
}

TEST(DiscoveryKey, RidsMatchOnlyNeighbouringEpochsAndTheRightKey)
{
    const Bytes key = randomBytes(32);
    const std::string rid = discoveryRid(key, 500);
    EXPECT_EQ(rid.size(), 22u);
    EXPECT_TRUE(discoveryRidMatches(key, rid, 499));
    EXPECT_TRUE(discoveryRidMatches(key, rid, 500));
    EXPECT_TRUE(discoveryRidMatches(key, rid, 501));
    EXPECT_FALSE(discoveryRidMatches(key, rid, 502));
    EXPECT_FALSE(discoveryRidMatches(randomBytes(32), rid, 500));
    EXPECT_FALSE(discoveryRidMatches(key, "short", 500));
    EXPECT_NE(discoveryRid(key, 501), rid);
}

TEST(DiscoveryKey, LabelsAreDnsSafeAndRotate)
{
    const Bytes key = randomBytes(32);
    const std::string label = discoveryLabel(key, 7, "instance");
    EXPECT_TRUE(std::regex_match(label, std::regex("[a-z2-7]{16}")));
    EXPECT_NE(discoveryLabel(key, 8, "instance"), label);
    EXPECT_NE(discoveryLabel(key, 7, "host"), label);
}
