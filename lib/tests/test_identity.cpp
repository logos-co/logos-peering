#include "logos/peering/fs.h"
#include "logos/peering/identity.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <regex>

using namespace logos::peering;
namespace fs = std::filesystem;

namespace {

fs::path freshDir(const std::string& name)
{
    const fs::path dir = fs::temp_directory_path() / ("peering-test-" + name + "-" + newUuidV4());
    fs::remove_all(dir);
    return dir;
}

} // namespace

TEST(Identity, UuidsAreCanonicalVersion4)
{
    const std::string uuid = newUuidV4();
    EXPECT_TRUE(isUuid(uuid));
    EXPECT_EQ(uuid[14], '4');
    EXPECT_NE(newUuidV4(), uuid);
    EXPECT_FALSE(isUuid("E0B64E6A-0000-4000-8000-000000000000"));
    EXPECT_FALSE(isUuid("e0b64e6a00004000800000000000000000"));
}

TEST(Identity, CreatedOnceThenReloaded)
{
    const fs::path dir = freshDir("identity");
    std::string error;
    const auto first = loadOrCreateIdentity(dir, &error);
    ASSERT_TRUE(first.has_value()) << error;
    const auto second = loadOrCreateIdentity(dir, &error);
    ASSERT_TRUE(second.has_value()) << error;
    EXPECT_EQ(first->uuid, second->uuid);
    EXPECT_EQ(first->rootSpki(), second->rootSpki());
    EXPECT_TRUE(std::regex_match(first->displayId(),
                                 std::regex("[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}")));
#ifndef _WIN32
    EXPECT_EQ(fs::status(dir / "root.key.pem").permissions() & fs::perms::all,
              fs::perms::owner_read | fs::perms::owner_write);
    EXPECT_EQ(fs::status(dir).permissions() & fs::perms::all, fs::perms::owner_all);
#endif
    fs::remove_all(dir);
}

TEST(Identity, AnIncompleteOrMismatchedIdentityIsRefused)
{
    const fs::path dir = freshDir("damaged");
    ASSERT_TRUE(loadOrCreateIdentity(dir).has_value());
    const auto otherDir = freshDir("other");
    ASSERT_TRUE(loadOrCreateIdentity(otherDir).has_value());
    fs::copy_file(otherDir / "root.key.pem", dir / "root.key.pem",
                  fs::copy_options::overwrite_existing);
    std::string error;
    EXPECT_FALSE(loadOrCreateIdentity(dir, &error).has_value());
    EXPECT_NE(error.find("damaged"), std::string::npos);

    fs::remove(dir / "root.cert.pem");
    EXPECT_FALSE(loadOrCreateIdentity(dir, &error).has_value());
    EXPECT_NE(error.find("incomplete"), std::string::npos);
    fs::remove_all(dir);
    fs::remove_all(otherDir);
}
