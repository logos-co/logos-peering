#include "logos/peering/audit.h"
#include "logos/peering/fs.h"
#include "logos/peering/identity.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <sstream>

using namespace logos::peering;
namespace fs = std::filesystem;

TEST(Audit, AppendsOneJsonLinePerEvent)
{
    const fs::path file = fs::temp_directory_path() / ("audit-" + newUuidV4() + ".jsonl");
    AuditLog log(file);
    log.record("route.denied", {{"peer", "p"}, {"consumer", "wallet"}});
    log.record("route.evaluation_failed", {{"reason", "timeout"}});
    const auto text = readFile(file);
    ASSERT_TRUE(text.has_value());
    std::istringstream lines(*text);
    std::string line;
    std::vector<nlohmann::json> events;
    while (std::getline(lines, line)) events.push_back(nlohmann::json::parse(line));
    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0]["event"], "route.denied");
    EXPECT_EQ(events[0]["consumer"], "wallet");
    EXPECT_TRUE(events[1].contains("ts"));
    fs::remove(file);
}
