#include "logos/peering/tickets.h"

#include <gtest/gtest.h>

using namespace logos::peering;
using namespace std::chrono_literals;

namespace {

struct FakeClock {
    TicketStore::Clock::time_point now = TicketStore::Clock::time_point(1000s);
    TicketStore::Now fn()
    {
        return [this] { return now; };
    }
};

} // namespace

TEST(Tickets, RedeemedExactlyOnce)
{
    TicketStore store;
    const std::string ticket = store.mint({{"target", "storage_module"}});
    EXPECT_EQ(ticket.size(), 43u);
    const auto first = store.redeem(ticket);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ((*first)["target"], "storage_module");
    EXPECT_FALSE(store.redeem(ticket).has_value());
}

TEST(Tickets, ExpireAfterTheirTtl)
{
    FakeClock clock;
    TicketStore store(30s, clock.fn());
    const std::string ticket = store.mint({});
    clock.now += 31s;
    EXPECT_FALSE(store.redeem(ticket).has_value());
    EXPECT_EQ(store.live(), 0u);
}

TEST(Tickets, TtlIsClampedToSixtySeconds)
{
    FakeClock clock;
    TicketStore store(3600s, clock.fn());
    const std::string ticket = store.mint({});
    clock.now += 61s;
    EXPECT_FALSE(store.redeem(ticket).has_value());
}

TEST(Tickets, AFailedCheckStillBurnsTheTicket)
{
    TicketStore store;
    const std::string ticket = store.mint({{"client_spki", "a"}});
    EXPECT_FALSE(store.redeem(ticket, [](const nlohmann::json& r) { return r["client_spki"] == "b"; }));
    EXPECT_FALSE(store.redeem(ticket).has_value());
}

TEST(Tickets, GarbageAndUnknownTicketsAreRefused)
{
    TicketStore store;
    store.mint({});
    EXPECT_FALSE(store.redeem("").has_value());
    EXPECT_FALSE(store.redeem("not-base64!").has_value());
    EXPECT_FALSE(store.redeem(std::string(43, 'A')).has_value());
    EXPECT_EQ(store.live(), 1u);
}

TEST(Tickets, TheStoreHoldsOnlyDigests)
{
    const std::string ticket = TicketStore().mint({});
    EXPECT_NE(TicketStore::digestOf(ticket), ticket);
    EXPECT_EQ(TicketStore::digestOf(ticket).size(), 43u);
}
