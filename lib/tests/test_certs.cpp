#include "logos/peering/certs.h"

#include <gtest/gtest.h>

#include <openssl/x509v3.h>

using namespace logos::peering;
using namespace std::chrono_literals;

namespace {

struct Root {
    PKey key = generateP256();
    Cert cert = makeRootCertificate(key.get(), 24h * 365);
};

Cert leafFor(const Root& root, Role role, const PKey& subject)
{
    return issueLeaf(root.key.get(), root.cert.get(), role, spkiDer(subject.get()), 24h);
}

} // namespace

TEST(Certs, RootIsAPathLengthZeroCa)
{
    Root root;
    EXPECT_NE(X509_get_extension_flags(root.cert.get()) & EXFLAG_CA, 0u);
    EXPECT_EQ(X509_get_pathlen(root.cert.get()), 0);
    EXPECT_FALSE(leafRole(root.cert.get()).has_value());
}

TEST(Certs, EachLeafCarriesExactlyItsRole)
{
    Root root;
    const PKey subject = generateP256();
    for (const Role role : {Role::Control, Role::Provider, Role::Client}) {
        const Cert leaf = leafFor(root, role, subject);
        ASSERT_TRUE(leaf);
        EXPECT_EQ(leafRole(leaf.get()), role);
        EXPECT_EQ(verifyLeaf(leaf.get(), root.cert.get(), role), "") << roleName(role);
        for (const Role other : {Role::Control, Role::Provider, Role::Client})
            if (other != role) EXPECT_NE(verifyLeaf(leaf.get(), root.cert.get(), other), "");
        EXPECT_EQ(spkiDer(leaf.get()), spkiDer(subject.get()));
    }
}

TEST(Certs, ALeafFromAnotherRootIsRefused)
{
    Root mine;
    Root theirs;
    const PKey subject = generateP256();
    const Cert leaf = leafFor(theirs, Role::Provider, subject);
    EXPECT_NE(verifyLeaf(leaf.get(), mine.cert.get(), Role::Provider), "");
}

TEST(Certs, ALeafCannotIssueFurtherLeaves)
{
    Root root;
    const PKey middleKey = generateP256();
    const Cert middle = leafFor(root, Role::Control, middleKey);
    const PKey subject = generateP256();
    const Cert grandchild =
        issueLeaf(middleKey.get(), middle.get(), Role::Client, spkiDer(subject.get()), 24h);
    // Anchored at the root, the chain breaks at the CA:FALSE middle.
    EXPECT_NE(verifyLeaf(grandchild.get(), root.cert.get(), Role::Client), "");
}

TEST(Certs, RoleNamesRoundTrip)
{
    for (const Role role : {Role::Control, Role::Provider, Role::Client})
        EXPECT_EQ(roleFromName(roleName(role)), role);
    EXPECT_FALSE(roleFromName("root").has_value());
    EXPECT_NE(roleOid(Role::Control), roleOid(Role::Client));
}

TEST(Certs, IssuingForANonP256KeyFails)
{
    Root root;
    PKey p384(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384"));
    ASSERT_TRUE(p384);
    EXPECT_THROW(issueLeaf(root.key.get(), root.cert.get(), Role::Client, spkiDer(p384.get()), 24h),
                 std::runtime_error);
}
