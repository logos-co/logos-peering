#include "logos/peering/crypto.h"

#include <gtest/gtest.h>

#include <openssl/evp.h>

using namespace logos::peering;

TEST(Crypto, Base64urlRoundTripsEveryLength)
{
    for (std::size_t n = 0; n < 40; ++n) {
        const Bytes data = randomBytes(n);
        const auto decoded = fromBase64url(base64url(data));
        ASSERT_TRUE(decoded.has_value()) << n;
        EXPECT_EQ(*decoded, data) << n;
    }
}

TEST(Crypto, Base64urlRefusesNonCanonicalAndForeignText)
{
    EXPECT_FALSE(fromBase64url("A").has_value());
    EXPECT_FALSE(fromBase64url("AB+/").has_value());
    EXPECT_FALSE(fromBase64url("AB==").has_value());
    // "AR" decodes 0x01 with two stray bits set; only "AQ" is canonical.
    EXPECT_FALSE(fromBase64url("AR").has_value());
    ASSERT_TRUE(fromBase64url("AQ").has_value());
    EXPECT_EQ(*fromBase64url("AQ"), Bytes{0x01});
}

TEST(Crypto, DigestsMatchKnownVectors)
{
    EXPECT_EQ(hex(sha256(toBytes("abc"))),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(hex(blake3(Bytes{})),
              "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    // RFC 4231, test case 2.
    EXPECT_EQ(hex(hmacSha256(toBytes("Jefe"), toBytes("what do ya want for nothing?"))),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(Crypto, ConstantTimeEqualComparesLengthAndContent)
{
    EXPECT_TRUE(constantTimeEqual(Bytes{1, 2}, Bytes{1, 2}));
    EXPECT_FALSE(constantTimeEqual(Bytes{1, 2}, Bytes{1, 3}));
    EXPECT_FALSE(constantTimeEqual(Bytes{1, 2}, Bytes{1, 2, 3}));
    EXPECT_TRUE(constantTimeEqual(Bytes{}, Bytes{}));
}

TEST(Crypto, KeysAndSpkiRoundTrip)
{
    const PKey key = generateP256();
    ASSERT_TRUE(isP256(key.get()));
    const PKey reloaded = privateKeyFromPem(privateKeyPem(key.get()));
    ASSERT_TRUE(reloaded);
    EXPECT_EQ(spkiDer(key.get()), spkiDer(reloaded.get()));

    const Bytes spki = spkiDer(key.get());
    const PKey pub = publicKeyFromSpki(spki);
    ASSERT_TRUE(pub);
    EXPECT_EQ(spkiDer(pub.get()), spki);
    EXPECT_EQ(spkiPin(spki).rfind("sha256:", 0), 0u);

    Bytes trailing = spki;
    trailing.push_back(0);
    EXPECT_FALSE(publicKeyFromSpki(trailing));
    EXPECT_FALSE(privateKeyFromPem("not a key"));
}

TEST(Crypto, CsrProvesPossessionOfAP256Key)
{
    const PKey key = generateP256();
    const auto spki = spkiFromCsrPem(makeCsrPem(key.get()));
    ASSERT_TRUE(spki.has_value());
    EXPECT_EQ(*spki, spkiDer(key.get()));
    EXPECT_FALSE(spkiFromCsrPem("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n").has_value());

    PKey p384(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384"));
    ASSERT_TRUE(p384);
    EXPECT_FALSE(spkiFromCsrPem(makeCsrPem(p384.get())).has_value());
}

TEST(Crypto, FramingIsUnambiguous)
{
    Bytes a;
    appendFramed(a, toBytes("ab"));
    appendFramed(a, toBytes("c"));
    Bytes b;
    appendFramed(b, toBytes("a"));
    appendFramed(b, toBytes("bc"));
    EXPECT_NE(a, b);
}
