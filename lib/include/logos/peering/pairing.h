#pragma once

// Commit-then-reveal pairing check: the initiator commits to its nonce before it
// sees the responder's, so a relay cannot steer both sides to the same code.

#include "logos/peering/crypto.h"

#include <string>

namespace logos::peering {

inline constexpr std::size_t kPairingNonceSize = 32;

Bytes pairingCommitment(const Bytes& nonce);
bool pairingRevealMatches(const Bytes& commitment, const Bytes& nonce);

// Six digits both screens show. `rootSpki*` are the two runtimes' root keys and
// `exporter` the TLS exporter (RFC 9266) of the connection that carried pairing.
std::string pairingCode(const Bytes& rootSpkiInitiator, const Bytes& rootSpkiResponder,
                        const Bytes& nonceInitiator, const Bytes& nonceResponder,
                        const Bytes& exporter);

} // namespace logos::peering
