#pragma once

// An IdentitySource holding the root key in this process, for a tool with no
// runtime of its own (logosctl's remote mode). A runtime keeps its root in
// peering_identity instead.

#include "logos/peering/identity.h"
#include "logos/peering/service.h"

#include <filesystem>
#include <mutex>

namespace logos::peering {

class LocalIdentity : public IdentitySource {
public:
    // Reads the identity from `dir`, or creates it there, on first use.
    explicit LocalIdentity(std::filesystem::path dir);

    std::optional<Info> info(std::string* error) override;
    std::optional<std::string> issue(Role role, const Bytes& spki, std::chrono::seconds validity,
                                     std::string* error) override;

private:
    bool loadLocked(std::string* error);

    std::filesystem::path dir_;
    std::mutex mutex_;
    std::optional<RuntimeIdentity> identity_;
};

} // namespace logos::peering
