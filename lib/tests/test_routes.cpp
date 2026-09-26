#include "logos/peering/routes.h"

#include <gtest/gtest.h>

using namespace logos::peering;
using namespace std::chrono_literals;

namespace {

struct FakeClock {
    RouteTable::Clock::time_point now = RouteTable::Clock::time_point(1000s);
    RouteTable::Now fn()
    {
        return [this] { return now; };
    }
};

Route sample(const std::string& peer, const std::string& target = "storage_module")
{
    Route r;
    r.peer = peer;
    r.consumer = "files_ui";
    r.target = target;
    r.scope = "calls";
    r.clientPin = "sha256:x";
    return r;
}

} // namespace

TEST(Routes, AddFindRenewExpire)
{
    FakeClock clock;
    RouteTable table(clock.fn());
    const Route route = table.add(sample("p1"), 300s);
    EXPECT_FALSE(route.id.empty());
    EXPECT_TRUE(table.find(route.id).has_value());
    clock.now += 200s;
    EXPECT_FALSE(table.renew(route.id, "p2", 300s).has_value()); // another peer
    EXPECT_TRUE(table.renew(route.id, "p1", 300s).has_value());
    clock.now += 250s;
    EXPECT_TRUE(table.find(route.id).has_value());
    clock.now += 60s;
    EXPECT_FALSE(table.find(route.id).has_value());
}

TEST(Routes, RevocationBumpsTheGenerationAndDropsSessions)
{
    RouteTable table;
    const Route a = table.add(sample("p1"), 300s);
    const Route b = table.add(sample("p2"), 300s);
    EXPECT_EQ(a.generation, 0u);
    ASSERT_TRUE(table.bindSession("exp-a", a.id));
    EXPECT_EQ(table.revokePeer("p1"), 1u);
    EXPECT_FALSE(table.find(a.id).has_value());
    EXPECT_FALSE(table.sessionRoute("exp-a").has_value());
    EXPECT_TRUE(table.find(b.id).has_value());
    EXPECT_EQ(table.add(sample("p1"), 300s).generation, 1u);
}

TEST(Routes, SessionsAreIdempotentPerConnectionOnly)
{
    RouteTable table;
    const Route a = table.add(sample("p1"), 300s);
    const Route b = table.add(sample("p1"), 300s);
    EXPECT_TRUE(table.bindSession("exp", a.id));
    EXPECT_TRUE(table.bindSession("exp", a.id));
    EXPECT_FALSE(table.bindSession("exp", b.id));
    EXPECT_FALSE(table.bindSession("other", "no-such-route"));
    EXPECT_EQ(table.sessionRoute("exp"), a.id);
}

TEST(Routes, ListingByPeerAndTarget)
{
    RouteTable table;
    table.add(sample("p1", "storage_module"), 300s);
    table.add(sample("p1", "core_service"), 300s);
    table.add(sample("p2", "storage_module"), 300s);
    EXPECT_EQ(table.forPeer("p1").size(), 2u);
    EXPECT_EQ(table.forTarget("storage_module").size(), 2u);
}
