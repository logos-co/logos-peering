#include "logos/peering/certs.h"
#include "logos/peering/enrollment.h"
#include "logos/peering/identity.h"

#include <gtest/gtest.h>

#include <filesystem>

using namespace logos::peering;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

Enrollment makePeer(const std::string& alias)
{
    const PKey root = generateP256();
    const Cert anchor = makeRootCertificate(root.get(), 24h);
    Enrollment e;
    e.runtimeInstanceId = newUuidV4();
    e.trustAnchorPem = certPem(anchor.get());
    e.subjectPublicKeys = {spkiPin(spkiDer(generateP256().get()))};
    e.alias = alias;
    e.displayName = "Office server";
    return e;
}

} // namespace

TEST(Enrollment, JsonRoundTripAndValidation)
{
    const Enrollment e = makePeer("office");
    const auto back = Enrollment::fromJson(e.toJson());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->toJson(), e.toJson());

    auto broken = e.toJson();
    broken["subject_public_keys"] = nlohmann::json::array();
    EXPECT_FALSE(Enrollment::fromJson(broken).has_value());
    broken = e.toJson();
    broken["runtime_instance_id"] = "nope";
    EXPECT_FALSE(Enrollment::fromJson(broken).has_value());
    for (const auto& uses : {nlohmann::json::array(), nlohmann::json{"root"}, nlohmann::json{"runtime-control"},
                             nlohmann::json{"provider-access", "provider-access"}}) {
        broken = e.toJson();
        broken["uses"] = uses;
        EXPECT_FALSE(Enrollment::fromJson(broken).has_value()) << uses.dump();
    }
    broken = e.toJson();
    broken["trust_anchor"] = "garbage";
    EXPECT_FALSE(Enrollment::fromJson(broken).has_value());
}

TEST(Enrollment, AnOperatorRoleLoadsAsRuntimeControl)
{
    auto doc = makePeer("office").toJson();
    doc.erase("uses");
    doc.erase("granted_uses");
    doc["role"] = "operator";
    doc["granted_role"] = "peer";
    const auto e = Enrollment::fromJson(doc);
    ASSERT_TRUE(e.has_value());
    EXPECT_TRUE(e->runtimeControl());
    EXPECT_FALSE(e->grantedRuntimeControl());
    EXPECT_EQ(e->toJson()["uses"], nlohmann::json({"provider-access", "runtime-control"}));
    EXPECT_FALSE(e->toJson().contains("role"));
}

TEST(Enrollment, StoreRefusesCollisions)
{
    EnrollmentStore store(fs::temp_directory_path() / ("peers-" + newUuidV4() + ".json"));
    const Enrollment office = makePeer("office");
    std::string error;
    ASSERT_TRUE(store.add(office, &error)) << error;

    Enrollment sameUuid = makePeer("other");
    sameUuid.runtimeInstanceId = office.runtimeInstanceId;
    EXPECT_FALSE(store.add(sameUuid, &error));

    Enrollment sameRoot = makePeer("third");
    sameRoot.trustAnchorPem = office.trustAnchorPem;
    EXPECT_FALSE(store.add(sameRoot, &error));

    EXPECT_FALSE(store.add(makePeer("office"), &error));
    EXPECT_TRUE(store.add(makePeer("laptop"), &error)) << error;
    EXPECT_EQ(store.all().size(), 2u);
    EXPECT_TRUE(store.findByAnchorPin(office.anchorPin()).has_value());
}

TEST(Enrollment, SaveLoadUpdateRemove)
{
    const fs::path file = fs::temp_directory_path() / ("peers-" + newUuidV4() + ".json");
    const Enrollment office = makePeer("office");
    {
        EnrollmentStore store(file);
        ASSERT_TRUE(store.add(office));
        ASSERT_TRUE(store.save());
    }
    EnrollmentStore store(file);
    std::string error;
    ASSERT_TRUE(store.load(&error)) << error;
    ASSERT_TRUE(store.find(office.runtimeInstanceId).has_value());

    Enrollment renamed = office;
    renamed.alias = "hq";
    EXPECT_FALSE(store.update(renamed, &error)); // same revision
    renamed.revision = 2;
    EXPECT_TRUE(store.update(renamed, &error)) << error;
    EXPECT_TRUE(store.findByAlias("hq").has_value());
    EXPECT_TRUE(store.remove(office.runtimeInstanceId));
    EXPECT_FALSE(store.remove(office.runtimeInstanceId));
    fs::remove(file);
}
