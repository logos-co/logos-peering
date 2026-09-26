#include "logos/peering/pairing.h"

#include <cstdio>

namespace logos::peering {
namespace {

Bytes labelled(const char* label) { return toBytes(label); }

} // namespace

Bytes pairingCommitment(const Bytes& nonce)
{
    Bytes input = labelled("logos-pair-commit-v1");
    appendFramed(input, nonce);
    return sha256(input);
}

bool pairingRevealMatches(const Bytes& commitment, const Bytes& nonce)
{
    return nonce.size() == kPairingNonceSize && constantTimeEqual(commitment, pairingCommitment(nonce));
}

std::string pairingCode(const Bytes& rootSpkiInitiator, const Bytes& rootSpkiResponder,
                        const Bytes& nonceInitiator, const Bytes& nonceResponder,
                        const Bytes& exporter)
{
    Bytes input = labelled("logos-pair-code-v1");
    appendFramed(input, rootSpkiInitiator);
    appendFramed(input, rootSpkiResponder);
    appendFramed(input, nonceInitiator);
    appendFramed(input, nonceResponder);
    appendFramed(input, exporter);
    const Bytes digest = sha256(input);
    const std::uint32_t value = (static_cast<std::uint32_t>(digest[0]) << 24)
                                | (static_cast<std::uint32_t>(digest[1]) << 16)
                                | (static_cast<std::uint32_t>(digest[2]) << 8) | digest[3];
    char code[8] = {0};
    std::snprintf(code, sizeof code, "%06u", static_cast<unsigned>(value % 1000000u));
    return code;
}

} // namespace logos::peering
