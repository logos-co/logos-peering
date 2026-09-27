#include "logos/peering/config.h"

#include <gtest/gtest.h>

using namespace logos::peering;
using json = nlohmann::json;

namespace {

const char* kRuntime = "0f8fad5b-d9cb-469f-a165-70867728950e";

json example()
{
    return {{"name", "office-server"},
            {"shell", "logoscore"},
            {"control", {{"enabled", true}, {"host", "0.0.0.0"}, {"port", 7443}}},
            {"exports", {{"enabled", true}, {"ports", "7450-7499"},
                         {"modules", {{"monerod_module", {{"events", true}}}}}}},
            {"runtime_control", false},
            {"announce", true},
            {"browse", true},
            {"imports", {{"wallet_backend", {{"from", kRuntime}, {"allowed_callers", {"wallet_ui"}}}}}}};
}

} // namespace

TEST(Config, TheDocumentedShapeParses)
{
    std::string error;
    const auto config = parsePeeringConfig(example(), &error);
    ASSERT_TRUE(config) << error;
    EXPECT_EQ(config->name, "office-server");
    EXPECT_EQ(config->shell, "logoscore");
    EXPECT_TRUE(config->control);
    EXPECT_EQ(config->controlPort, 7443);
    EXPECT_EQ(config->exportPortMin, 7450);
    EXPECT_EQ(config->exportPortMax, 7499);
    ASSERT_TRUE(config->exportModules.count("monerod_module"));
    EXPECT_TRUE(config->exportModules.at("monerod_module").events);
    ASSERT_TRUE(config->imports.count("wallet_backend"));
    const auto& rule = config->imports.at("wallet_backend");
    EXPECT_EQ(rule.module, "wallet_backend");
    EXPECT_EQ(rule.prefer, "remote");
    EXPECT_EQ(rule.allowedCallers, std::vector<std::string>{"wallet_ui"});
}

TEST(Config, NothingConfiguredIsEverythingOff)
{
    const auto config = parsePeeringConfig(json());
    ASSERT_TRUE(config);
    EXPECT_FALSE(config->control);
    EXPECT_FALSE(config->exports);
    EXPECT_FALSE(config->announce);
    EXPECT_FALSE(config->browse);
    EXPECT_TRUE(config->imports.empty());
}

TEST(Config, AnUnknownKeyIsAnError)
{
    json doc = example();
    doc["control"]["tls"] = true;
    std::string error;
    EXPECT_FALSE(parsePeeringConfig(doc, &error));
    EXPECT_NE(error.find("control.tls"), std::string::npos);
    doc = example();
    doc["relay"] = true;
    EXPECT_FALSE(parsePeeringConfig(doc));
}

TEST(Config, ExportsAndAnnouncingNeedTheControlEndpoint)
{
    json doc = example();
    doc["control"]["enabled"] = false;
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc["exports"]["enabled"] = false;
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc["announce"] = false;
    EXPECT_TRUE(parsePeeringConfig(doc));
}

TEST(Config, ReservedNamesAreNeitherImportedNorExported)
{
    for (const char* name : {"core_service", "capability_module", "peering_module", "logos_anything",
                             "Core_Service", "peering_extra"}) {
        json doc = example();
        doc["exports"]["modules"] = {{name, json::object()}};
        EXPECT_FALSE(parsePeeringConfig(doc)) << name;
        doc = example();
        doc["imports"] = {{name, {{"from", kRuntime}}}};
        EXPECT_FALSE(parsePeeringConfig(doc)) << name;
        doc = example();
        doc["imports"] = {{"fine_name", {{"from", kRuntime}, {"module", name}}}};
        EXPECT_FALSE(parsePeeringConfig(doc)) << name;
    }
}

TEST(Config, ImportsNameARuntimeAndValidConsumers)
{
    json doc = example();
    doc["imports"]["wallet_backend"]["from"] = "office";
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc = example();
    doc["imports"]["wallet_backend"]["allowed_callers"] = {"has space"};
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc = example();
    doc["imports"]["wallet_backend"]["prefer"] = "either";
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc = example();
    doc["imports"]["wallet_backend"]["allowed_callers"] = {"runtime", "@op:alice", "wallet_ui"};
    EXPECT_TRUE(parsePeeringConfig(doc));
    doc["imports"]["wallet_backend"]["allowed_callers"] = {"*"};
    EXPECT_TRUE(parsePeeringConfig(doc));
}

TEST(Config, ANameIsNotBothImportedAndExported)
{
    json doc = example();
    doc["imports"] = {{"monerod_module", {{"from", kRuntime}}}};
    EXPECT_FALSE(parsePeeringConfig(doc));
}

TEST(Config, PortRangesTakeThreeForms)
{
    json doc = example();
    doc["exports"]["ports"] = 7460;
    auto config = parsePeeringConfig(doc);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->exportPortMin, 7460);
    EXPECT_EQ(config->exportPortMax, 7460);
    doc["exports"]["ports"] = "7461";
    config = parsePeeringConfig(doc);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->exportPortMax, 7461);
    for (const char* bad : {"7499-7450", "x-1", "0-10", "1-70000", ""}) {
        doc["exports"]["ports"] = bad;
        EXPECT_FALSE(parsePeeringConfig(doc)) << bad;
    }
}

TEST(Config, ALocalInviteIsOnOrDescribed)
{
    json doc = example();
    doc["control"]["local_invite"] = true;
    auto config = parsePeeringConfig(doc);
    ASSERT_TRUE(config);
    EXPECT_TRUE(config->localInvite);
    EXPECT_FALSE(config->localInviteRuntimeControl);
    doc["control"]["local_invite"] = {{"path", "/tmp/x/local-invite"}, {"runtime_control", true}};
    config = parsePeeringConfig(doc);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->localInvitePath, "/tmp/x/local-invite");
    EXPECT_TRUE(config->localInviteRuntimeControl);
    doc["control"]["local_invite"] = {{"runtime_control", "yes"}};
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc["control"]["local_invite"] = {{"role", "operator"}};
    EXPECT_FALSE(parsePeeringConfig(doc));
    doc["control"]["local_invite"] = {{"ttl", 5}};
    EXPECT_FALSE(parsePeeringConfig(doc));
}

TEST(Config, ALocalInviteAllowsExportsOnly)
{
    json doc = example();
    doc["control"]["local_invite"] = {{"allow", {"*", "monerod_module"}}};
    const auto config = parsePeeringConfig(doc);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->localInviteAllow, (std::vector<std::string>{"*", "monerod_module"}));
    for (const json& bad : {json("*"), json({"core_service"}), json({"peering_module"}), json({1})}) {
        doc["control"]["local_invite"] = {{"allow", bad}};
        EXPECT_FALSE(parsePeeringConfig(doc)) << bad.dump();
    }
}
