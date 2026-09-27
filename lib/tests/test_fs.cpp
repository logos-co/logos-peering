#include "logos/peering/fs.h"

#include "owner_only.h"

#include <gtest/gtest.h>

#include <random>

using namespace logos::peering;
namespace fs = std::filesystem;

TEST(Fs, KeysInvitesAndLogsAreTheOwnersAlone)
{
    const fs::path dir = fs::temp_directory_path() / ("peering-fs-" + std::to_string(std::random_device{}()));
    ASSERT_TRUE(ensurePrivateDir(dir / "state"));
    EXPECT_TRUE(ownerOnly(dir / "state"));
    ASSERT_TRUE(writeFileAtomically(dir / "state" / "root.key", "secret"));
    EXPECT_TRUE(ownerOnly(dir / "state" / "root.key"));
    // Replacing a file keeps it private and leaves no temporary behind.
    ASSERT_TRUE(writeFileAtomically(dir / "state" / "root.key", "again"));
    EXPECT_EQ(readFile(dir / "state" / "root.key"), "again");
    EXPECT_FALSE(fs::exists(dir / "state" / "root.key.tmp"));
    // Outside a private directory too (a configured local-invite path).
    fs::create_directories(dir / "shared");
    ASSERT_TRUE(writeFileAtomically(dir / "shared" / "local-invite", "invite"));
    EXPECT_TRUE(ownerOnly(dir / "shared" / "local-invite"));
    ASSERT_TRUE(appendLine(dir / "shared" / "audit.log", "one"));
    ASSERT_TRUE(appendLine(dir / "shared" / "audit.log", "two"));
    EXPECT_TRUE(ownerOnly(dir / "shared" / "audit.log"));
    EXPECT_EQ(readFile(dir / "shared" / "audit.log"), "one\ntwo\n");
    std::error_code ec;
    fs::remove_all(dir, ec);
    EXPECT_FALSE(ec) << ec.message();
}
