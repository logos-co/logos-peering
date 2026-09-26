#include "peering_identity_impl.h"

#include "logos/peering/certs.h"
#include "logos/peering/identity.h"

#include <logos_caller.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>

using namespace logos::peering;

namespace {

constexpr std::int64_t kMaxValiditySeconds = 90LL * 24 * 3600;

LogosMap fault(const std::string& code) { return LogosMap{{"error", code}}; }

bool fromPeeringModule() { return logos::currentCaller().isModule("peering_module"); }

} // namespace

struct PeeringIdentityImpl::State {
    std::mutex mutex;
    std::optional<RuntimeIdentity> identity;
    std::string error = "the identity is not loaded yet";
};

PeeringIdentityImpl::PeeringIdentityImpl() : m_state(std::make_unique<State>()) {}

PeeringIdentityImpl::~PeeringIdentityImpl() = default;

void PeeringIdentityImpl::onContextReady()
{
    std::lock_guard<std::mutex> lock(m_state->mutex);
    if (instancePersistencePath().empty()) {
        m_state->error = "no persistence path";
        return;
    }
    std::string error;
    m_state->identity = loadOrCreateIdentity(
        std::filesystem::u8path(instancePersistencePath()) / "identity", &error);
    if (!m_state->identity) m_state->error = error;
}

LogosMap PeeringIdentityImpl::runtimeId()
{
    if (!fromPeeringModule()) return fault("NOT_AUTHORISED");
    std::lock_guard<std::mutex> lock(m_state->mutex);
    if (!m_state->identity) return fault("IDENTITY_UNAVAILABLE: " + m_state->error);
    return LogosMap{{"runtime_id", m_state->identity->uuid}};
}

LogosMap PeeringIdentityImpl::rootCertificate()
{
    if (!fromPeeringModule()) return fault("NOT_AUTHORISED");
    std::lock_guard<std::mutex> lock(m_state->mutex);
    if (!m_state->identity) return fault("IDENTITY_UNAVAILABLE: " + m_state->error);
    return LogosMap{{"root_pem", certPem(m_state->identity->rootCert.get())}};
}

LogosMap PeeringIdentityImpl::displayId()
{
    if (!fromPeeringModule()) return fault("NOT_AUTHORISED");
    std::lock_guard<std::mutex> lock(m_state->mutex);
    if (!m_state->identity) return fault("IDENTITY_UNAVAILABLE: " + m_state->error);
    return LogosMap{{"display_id", m_state->identity->displayId()}};
}

LogosMap PeeringIdentityImpl::issue(const std::string& role, const std::string& spki,
                                    int64_t validitySeconds)
{
    if (!fromPeeringModule()) return fault("NOT_AUTHORISED");
    const auto parsedRole = roleFromName(role);
    const auto der = fromBase64url(spki);
    if (!parsedRole || !der || validitySeconds <= 0) return fault("INVALID_ARGUMENT");
    const PKey key = publicKeyFromSpki(*der);
    if (!key || !isP256(key.get())) return fault("INVALID_ARGUMENT");
    std::lock_guard<std::mutex> lock(m_state->mutex);
    if (!m_state->identity) return fault("IDENTITY_UNAVAILABLE: " + m_state->error);
    try {
        const Cert leaf = issueLeaf(m_state->identity->rootKey.get(), m_state->identity->rootCert.get(),
                                    *parsedRole, *der,
                                    std::chrono::seconds(std::min(validitySeconds, kMaxValiditySeconds)));
        return LogosMap{{"leaf_pem", certPem(leaf.get())}};
    } catch (const std::exception& ex) {
        return fault(std::string("FAILED: ") + ex.what());
    }
}
