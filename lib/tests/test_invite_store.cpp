#include "logos/peering/identity.h"
#include "logos/peering/invite_store.h"

#include <gtest/gtest.h>

#include <filesystem>

using namespace logos::peering;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

struct FakeClock {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::time_point(1000000s);
    InviteStore::Now fn()
    {
        return [this] { return now; };
    }
};

} // namespace

TEST(InviteStore, SingleUseAndPersistedAsDigestsOnly)
{
    const fs::path file = fs::temp_directory_path() / ("invites-" + newUuidV4() + ".json");
    std::string secret;
    {
        InviteStore store(file);
        secret = store.issue("peer", 0s, "shell:logoscore");
    }
    const auto text = std::filesystem::exists(file);
    ASSERT_TRUE(text);
    InviteStore reloaded(file);
    ASSERT_TRUE(reloaded.load());
    const auto redeemed = reloaded.redeem(secret);
    ASSERT_TRUE(redeemed.has_value());
    EXPECT_EQ(redeemed->role, "peer");
    EXPECT_FALSE(reloaded.redeem(secret).has_value());
    fs::remove(file);
}

TEST(InviteStore, OperatorInvitesLiveAtMostFifteenMinutes)
{
    FakeClock clock;
    InviteStore store({}, clock.fn());
    const std::string secret = store.issue("operator", 24h, "@op:alice");
    clock.now += 16min;
    EXPECT_FALSE(store.redeem(secret).has_value());
    EXPECT_FALSE(store.anyLive());
}

TEST(InviteStore, PeerInvitesDefaultToADay)
{
    FakeClock clock;
    InviteStore store({}, clock.fn());
    const std::string secret = store.issue("peer", 0s, "shell:basecamp");
    clock.now += 23h;
    EXPECT_TRUE(store.anyLive());
    EXPECT_TRUE(store.redeem(secret).has_value());
}

TEST(InviteStore, UnknownRolesBecomePeer)
{
    InviteStore store;
    const std::string secret = store.issue("root", 0s, "x");
    const auto redeemed = store.redeem(secret);
    ASSERT_TRUE(redeemed.has_value());
    EXPECT_EQ(redeemed->role, "peer");
    EXPECT_FALSE(store.redeem("garbage").has_value());
}
