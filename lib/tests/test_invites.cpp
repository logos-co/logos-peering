#include "logos/peering/crypto.h"
#include "logos/peering/identity.h"
#include "logos/peering/invites.h"

#include <gtest/gtest.h>

using namespace logos::peering;

namespace {

Invite sample(const std::string& host)
{
    Invite invite;
    invite.runtimeId = newUuidV4();
    invite.rootDigest = base64url(sha256(randomBytes(64)));
    invite.secret = newInviteSecret();
    invite.host = host;
    invite.port = 7443;
    return invite;
}

} // namespace

TEST(Invites, RoundTripForEveryHostForm)
{
    for (const std::string host : {"office-server.local", "192.168.1.20", "fe80::1", "::1"}) {
        const Invite invite = sample(host);
        std::string error;
        const auto parsed = parseInvite("  " + formatInvite(invite) + "\n", &error);
        ASSERT_TRUE(parsed.has_value()) << host << ": " << error;
        EXPECT_EQ(parsed->runtimeId, invite.runtimeId);
        EXPECT_EQ(parsed->rootDigest, invite.rootDigest);
        EXPECT_EQ(parsed->secret, invite.secret);
        EXPECT_EQ(parsed->host, host);
        EXPECT_EQ(parsed->port, 7443);
    }
}

TEST(Invites, MalformedInvitesAreRefused)
{
    const std::string good = formatInvite(sample("host.local"));
    EXPECT_TRUE(parseInvite(good).has_value());
    for (const std::string bad : {
             std::string("logos-pair:v2:") + good.substr(14),
             good.substr(0, good.find('@')),
             good.substr(0, good.rfind(':')),
             good.substr(0, good.rfind(':')) + ":0",
             good.substr(0, good.rfind(':')) + ":65536",
             good.substr(0, good.rfind(':')) + ":80a",
             good.substr(0, good.find('@')) + "@-bad-.local:7443",
             good.substr(0, good.find('@')) + "@[fe80::1:7443",
             std::string("logos-pair:v1:NOT-A-UUID:") + good.substr(good.find(':', 14) + 1),
         })
        EXPECT_FALSE(parseInvite(bad).has_value()) << bad;
}

TEST(Invites, TheSecretDigestIsStableAndNotTheSecret)
{
    const std::string secret = newInviteSecret();
    EXPECT_EQ(inviteSecretDigest(secret), inviteSecretDigest(secret));
    EXPECT_NE(inviteSecretDigest(secret), secret);
    EXPECT_EQ(inviteSecretDigest("%%%"), "");
}
