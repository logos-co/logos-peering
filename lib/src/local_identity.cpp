#include "logos/peering/local_identity.h"

#include "logos/peering/certs.h"

#include <algorithm>

namespace logos::peering {

namespace {
// As peering_identity: no leaf outlives this.
constexpr std::chrono::seconds kMaxValidity{90LL * 24 * 3600};
} // namespace

LocalIdentity::LocalIdentity(std::filesystem::path dir) : dir_(std::move(dir)) {}

bool LocalIdentity::loadLocked(std::string* error)
{
    if (!identity_) identity_ = loadOrCreateIdentity(dir_, error);
    return identity_.has_value();
}

std::optional<IdentitySource::Info> LocalIdentity::info(std::string* error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!loadLocked(error)) return std::nullopt;
    return Info{identity_->uuid, certPem(identity_->rootCert.get()), identity_->displayId()};
}

std::optional<std::string> LocalIdentity::issue(Role role, const Bytes& spki,
                                                std::chrono::seconds validity, std::string* error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!loadLocked(error)) return std::nullopt;
    try {
        const Cert leaf = issueLeaf(identity_->rootKey.get(), identity_->rootCert.get(), role, spki,
                                    std::min(validity, kMaxValidity));
        return certPem(leaf.get());
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return std::nullopt;
    }
}

} // namespace logos::peering
