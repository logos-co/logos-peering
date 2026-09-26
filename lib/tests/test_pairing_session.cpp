#include "logos/peering/identity.h"
#include "logos/peering/pairing_session.h"

#include <gtest/gtest.h>

using namespace logos::peering;

namespace {

PairingParty party(const std::string& name)
{
    return PairingParty{newUuidV4(), spkiDer(generateP256().get()), name, randomBytes(32)};
}

struct Exchange {
    PairingParty a = party("Laptop");
    PairingParty b = party("Office server");
    Bytes exporter = randomBytes(32);
};

PairingResponder::RedeemInvite inviteGranting(std::optional<std::string> role, int* uses)
{
    return [role, uses](const std::string&) {
        if (uses) ++*uses;
        return role;
    };
}

} // namespace

TEST(PairingSession, CodePairingNeedsBothSides)
{
    Exchange x;
    PairingInitiator a(x.a, std::nullopt);
    PairingResponder b(x.b, {}, /*pairingWindowOpen=*/true);
    a.setTransport(x.b.rootSpki, x.exporter);
    b.setTransport(x.a.rootSpki, x.exporter);

    std::string error;
    const auto nonce = b.onHello(a.hello(), &error);
    ASSERT_TRUE(nonce.has_value()) << error;
    const auto reveal = a.onNonce(*nonce, &error);
    ASSERT_TRUE(reveal.has_value()) << error;
    ASSERT_TRUE(b.onReveal(*reveal, &error)) << error;
    EXPECT_EQ(a.code(), b.code());
    EXPECT_TRUE(a.needsConfirmation());
    EXPECT_TRUE(b.needsApproval());

    ASSERT_TRUE(b.onConfirm(a.confirm(), &error)) << error;
    EXPECT_FALSE(b.ready());
    b.approve();
    ASSERT_TRUE(b.ready());

    const auto outcome = a.onResult(b.result(), &error);
    ASSERT_TRUE(outcome.has_value()) << error;
    EXPECT_EQ(outcome->peerRuntimeId, x.b.runtimeId);
    EXPECT_EQ(outcome->peerAnnounceKey, x.b.announceKey);
    EXPECT_EQ(outcome->role, "peer");
    EXPECT_EQ(b.outcome().peerRuntimeId, x.a.runtimeId);
    EXPECT_EQ(b.outcome().peerAnnounceKey, x.a.announceKey);
}

TEST(PairingSession, ClosedWindowRefusesCodePairing)
{
    Exchange x;
    PairingInitiator a(x.a, std::nullopt);
    PairingResponder b(x.b, {}, false);
    b.setTransport(x.a.rootSpki, x.exporter);
    std::string error;
    EXPECT_FALSE(b.onHello(a.hello(), &error).has_value());
    EXPECT_NE(error.find("closed"), std::string::npos);
}

TEST(PairingSession, PeerInviteSkipsCodesAndApproval)
{
    Exchange x;
    int uses = 0;
    PairingInitiator a(x.a, std::string("secret"));
    PairingResponder b(x.b, inviteGranting("peer", &uses), false);
    a.setTransport(x.b.rootSpki, x.exporter);
    b.setTransport(x.a.rootSpki, x.exporter);
    const auto reveal = a.onNonce(*b.onHello(a.hello()));
    ASSERT_TRUE(b.onReveal(*reveal));
    EXPECT_FALSE(a.needsConfirmation());
    EXPECT_FALSE(b.needsApproval());
    ASSERT_TRUE(b.onConfirm(a.confirm()));
    EXPECT_TRUE(b.ready());
    EXPECT_EQ(uses, 1);
}

TEST(PairingSession, OperatorRoleNeedsAnOperatorInviteAndApproval)
{
    Exchange x;
    {
        PairingInitiator a(x.a, std::nullopt, "operator");
        PairingResponder b(x.b, {}, true);
        b.setTransport(x.a.rootSpki, x.exporter);
        EXPECT_FALSE(b.onHello(a.hello()).has_value());
    }
    PairingInitiator a(x.a, std::string("secret"), "operator");
    PairingResponder b(x.b, inviteGranting("operator", nullptr), false);
    a.setTransport(x.b.rootSpki, x.exporter);
    b.setTransport(x.a.rootSpki, x.exporter);
    ASSERT_TRUE(b.onReveal(*a.onNonce(*b.onHello(a.hello()))));
    ASSERT_TRUE(b.onConfirm(a.confirm()));
    EXPECT_EQ(b.grantedRole(), "operator");
    EXPECT_TRUE(b.needsApproval());
    EXPECT_FALSE(b.ready());
    b.approve();
    const auto outcome = a.onResult(b.result());
    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->role, "operator");
}

TEST(PairingSession, APeerInviteNeverGrantsOperator)
{
    Exchange x;
    PairingInitiator a(x.a, std::string("secret"), "operator");
    PairingResponder b(x.b, inviteGranting("peer", nullptr), false);
    b.setTransport(x.a.rootSpki, x.exporter);
    ASSERT_TRUE(b.onHello(a.hello()).has_value());
    EXPECT_EQ(b.grantedRole(), "peer");
}

TEST(PairingSession, AWrongRevealIsRefused)
{
    Exchange x;
    PairingInitiator a(x.a, std::nullopt);
    PairingResponder b(x.b, {}, true);
    a.setTransport(x.b.rootSpki, x.exporter);
    b.setTransport(x.a.rootSpki, x.exporter);
    ASSERT_TRUE(a.onNonce(*b.onHello(a.hello())).has_value());
    EXPECT_FALSE(b.onReveal({{"nonce", base64url(randomBytes(32))}}));
    EXPECT_TRUE(b.rejected());
    EXPECT_EQ(b.result()["status"], "rejected");
}

TEST(PairingSession, SelfPairingAndMalformedHellosAreRefused)
{
    Exchange x;
    PairingInitiator a(x.a, std::nullopt);
    {
        PairingResponder b(x.b, {}, true);
        b.setTransport(x.b.rootSpki, x.exporter); // "initiator" presents B's own root
        EXPECT_FALSE(b.onHello(a.hello()).has_value());
    }
    PairingResponder b(x.b, {}, true);
    b.setTransport(x.a.rootSpki, x.exporter);
    auto hello = a.hello();
    hello["display_name"] = "bad\nname";
    EXPECT_FALSE(b.onHello(hello).has_value());
}

TEST(PairingSession, ADeclinedResultReportsIt)
{
    Exchange x;
    PairingInitiator a(x.a, std::nullopt);
    PairingResponder b(x.b, {}, true);
    a.setTransport(x.b.rootSpki, x.exporter);
    b.setTransport(x.a.rootSpki, x.exporter);
    ASSERT_TRUE(b.onReveal(*a.onNonce(*b.onHello(a.hello()))));
    b.reject();
    std::string error;
    EXPECT_FALSE(a.onResult(b.result(), &error).has_value());
    EXPECT_NE(error.find("declined"), std::string::npos);
}
