#pragma once

// Issuer-side invites: only BLAKE3 digests of secrets are kept. An invite is
// consumed by the first successful redemption, and expires on its own.

#include "logos/peering/invites.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

struct IssuedInvite {
    std::string secretDigest;
    std::string role; // peer | runtime-control
    std::chrono::system_clock::time_point expires;
    std::string issuedBy;
};

class InviteStore {
public:
    using Now = std::function<std::chrono::system_clock::time_point()>;

    static constexpr std::chrono::hours kPeerTtl{24};
    static constexpr std::chrono::minutes kRuntimeControlTtl{15};

    explicit InviteStore(std::filesystem::path file = {}, Now now = {});

    bool load(std::string* error = nullptr);

    // Returns the secret; it is not stored. `ttl` is capped by the role's maximum.
    std::string issue(const std::string& role, std::chrono::seconds ttl, const std::string& issuedBy);

    // Consumes a live invite whose secret matches and that `accept` (if
    // given) approves, returning what it granted.
    std::optional<IssuedInvite> redeem(const std::string& secret,
                                       const std::function<bool(const IssuedInvite&)>& accept = {});
    // Withdraws the invite with this secret digest.
    bool revoke(const std::string& secretDigest);

    // Whether a live invite exists at all (the listener then admits unknown roots).
    bool anyLive();
    std::vector<IssuedInvite> live();

private:
    void purgeLocked();
    void saveLocked();

    std::filesystem::path file_;
    Now now_;
    std::mutex mutex_;
    std::vector<IssuedInvite> invites_;
};

} // namespace logos::peering
