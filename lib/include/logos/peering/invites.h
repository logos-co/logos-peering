#pragma once

// Invites: logos-pair:v1:<uuid>:<root-sha256>:<secret>@<host>:<port>
// The secret is single use; the issuer keeps only its BLAKE3 digest.

#include <cstdint>
#include <optional>
#include <string>

namespace logos::peering {

struct Invite {
    std::string runtimeId;  // issuer's UUID
    std::string rootDigest; // base64url SHA-256 of the issuer's root SPKI
    std::string secret;     // base64url of 32 random bytes
    std::string host;       // DNS name, IPv4, or IPv6 without brackets
    std::uint16_t port = 0;

    std::string rootPin() const { return "sha256:" + rootDigest; }
};

std::string formatInvite(const Invite& invite);
std::optional<Invite> parseInvite(const std::string& text, std::string* error = nullptr);

std::string newInviteSecret();
std::string inviteSecretDigest(const std::string& secret);

} // namespace logos::peering
