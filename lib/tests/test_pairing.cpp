#include "logos/peering/pairing.h"

#include <gtest/gtest.h>

#include <regex>

using namespace logos::peering;

TEST(Pairing, TheRevealMustMatchTheCommitment)
{
    const Bytes nonce = randomBytes(kPairingNonceSize);
    const Bytes commitment = pairingCommitment(nonce);
    EXPECT_TRUE(pairingRevealMatches(commitment, nonce));
    EXPECT_FALSE(pairingRevealMatches(commitment, randomBytes(kPairingNonceSize)));
    EXPECT_FALSE(pairingRevealMatches(commitment, Bytes(nonce.begin(), nonce.end() - 1)));
}

TEST(Pairing, TheCodeIsSixDigitsAndBindsEveryInput)
{
    const Bytes a = randomBytes(91), b = randomBytes(91), na = randomBytes(32), nb = randomBytes(32),
                x = randomBytes(32);
    const std::string code = pairingCode(a, b, na, nb, x);
    EXPECT_TRUE(std::regex_match(code, std::regex("[0-9]{6}")));
    EXPECT_EQ(pairingCode(a, b, na, nb, x), code);
    // Swapping roles or changing any input gives another code (with overwhelming probability).
    EXPECT_NE(pairingCode(b, a, nb, na, x), code);
    EXPECT_NE(pairingCode(a, b, na, nb, randomBytes(32)), code);
    EXPECT_NE(pairingCode(a, b, randomBytes(32), nb, x), code);
}

TEST(Pairing, ARelayYieldsDifferentCodesOnEachSide)
{
    // A relay runs two TLS connections, so each side sees its own exporter.
    const Bytes a = randomBytes(91), b = randomBytes(91), na = randomBytes(32), nb = randomBytes(32);
    int differing = 0;
    for (int i = 0; i < 20; ++i)
        if (pairingCode(a, b, na, nb, randomBytes(32)) != pairingCode(a, b, na, nb, randomBytes(32)))
            ++differing;
    EXPECT_GE(differing, 19);
}
