#pragma once

// The runtime's long-lived identity: a UUID v4 (spec) and a P-256 root that
// only ever signs role-marked leaves.

#include "logos/peering/crypto.h"

#include <filesystem>
#include <optional>
#include <string>

namespace logos::peering {

std::string newUuidV4();
// Canonical lowercase 8-4-4-4-12 hex.
bool isUuid(const std::string& text);

// SHA-256 of the root SPKI, 20 base32 characters in four groups of five.
std::string displayIdFor(const Bytes& rootSpki);

struct RuntimeIdentity {
    std::string uuid;
    PKey rootKey;
    Cert rootCert;

    Bytes rootSpki() const;
    std::string rootPin() const;
    std::string displayId() const;
};

// Reads identity.json, root.key.pem and root.cert.pem from `dir`, or creates them.
std::optional<RuntimeIdentity> loadOrCreateIdentity(const std::filesystem::path& dir,
                                                    std::string* error = nullptr);

} // namespace logos::peering
