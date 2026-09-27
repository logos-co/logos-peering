#include "logos/peering/pairing_session.h"

#include "logos/peering/identity.h"
#include "logos/peering/names.h"
#include "logos/peering/pairing.h"

namespace logos::peering {
namespace {

void setError(std::string* error, const std::string& text)
{
    if (error) *error = text;
}

std::optional<std::string> textField(const nlohmann::json& body, const char* key)
{
    const auto it = body.find(key);
    if (it == body.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

std::optional<Bytes> bytesField(const nlohmann::json& body, const char* key, std::size_t size)
{
    const auto text = textField(body, key);
    if (!text) return std::nullopt;
    auto raw = fromBase64url(*text);
    if (!raw || raw->size() != size) return std::nullopt;
    return raw;
}

// "operator" is what runtime-control was called before.
std::string roleName(const std::string& role)
{
    return role == "runtime-control" || role == "operator" ? "runtime-control" : "peer";
}

} // namespace

PairingInitiator::PairingInitiator(PairingParty self, std::optional<std::string> inviteSecret,
                                   std::string requestedRole)
    : self_(std::move(self))
    , invite_(std::move(inviteSecret))
    , role_(roleName(requestedRole))
    , nonce_(randomBytes(kPairingNonceSize))
{
}

nlohmann::json PairingInitiator::hello() const
{
    nlohmann::json body = {{"v", 1},
                           {"runtime_id", self_.runtimeId},
                           {"display_name", self_.displayName},
                           {"commitment", base64url(pairingCommitment(nonce_))},
                           {"role", role_}};
    if (invite_) body["invite"] = *invite_;
    return body;
}

void PairingInitiator::setTransport(Bytes responderRootSpki, Bytes exporter)
{
    peerRootSpki_ = std::move(responderRootSpki);
    exporter_ = std::move(exporter);
}

std::optional<nlohmann::json> PairingInitiator::onNonce(const nlohmann::json& body, std::string* error)
{
    const auto nonce = bytesField(body, "nonce", kPairingNonceSize);
    if (revealed_ || !nonce || peerRootSpki_.empty() || exporter_.empty()) {
        setError(error, "unexpected or malformed pair.nonce");
        return std::nullopt;
    }
    revealed_ = true;
    code_ = pairingCode(self_.rootSpki, peerRootSpki_, nonce_, *nonce, exporter_);
    return nlohmann::json{{"nonce", base64url(nonce_)}};
}

nlohmann::json PairingInitiator::confirm() const
{
    return {{"announce_key", base64url(self_.announceKey)}};
}

std::optional<PairingOutcome> PairingInitiator::onResult(const nlohmann::json& body, std::string* error)
{
    const auto status = textField(body, "status");
    if (!revealed_ || !status) {
        setError(error, "unexpected or malformed pair.result");
        return std::nullopt;
    }
    if (*status != "accepted") {
        setError(error, "the other side declined");
        return std::nullopt;
    }
    const auto runtimeId = textField(body, "runtime_id");
    const auto displayName = textField(body, "display_name");
    const auto announceKey = bytesField(body, "announce_key", 32);
    const auto granted = textField(body, "role");
    if (!runtimeId || !isUuid(*runtimeId) || !displayName || !isValidDisplayName(*displayName)
        || !announceKey || !granted || (*granted != "peer" && roleName(*granted) != "runtime-control")) {
        setError(error, "malformed pair.result");
        return std::nullopt;
    }
    return PairingOutcome{*runtimeId, *displayName, peerRootSpki_, *announceKey, roleName(*granted)};
}

PairingResponder::PairingResponder(PairingParty self, RedeemInvite redeemInvite, bool pairingWindowOpen)
    : self_(std::move(self)), redeemInvite_(std::move(redeemInvite)), windowOpen_(pairingWindowOpen)
{
}

void PairingResponder::setTransport(Bytes initiatorRootSpki, Bytes exporter)
{
    peerRootSpki_ = std::move(initiatorRootSpki);
    exporter_ = std::move(exporter);
}

std::optional<nlohmann::json> PairingResponder::onHello(const nlohmann::json& body, std::string* error)
{
    if (!commitment_.empty() || peerRootSpki_.empty() || exporter_.empty()) {
        setError(error, "unexpected pair.hello");
        return std::nullopt;
    }
    const auto version = body.find("v");
    const auto runtimeId = textField(body, "runtime_id");
    const auto displayName = textField(body, "display_name");
    const auto commitment = bytesField(body, "commitment", 32);
    const auto role = textField(body, "role");
    if (version == body.end() || *version != 1 || !runtimeId || !isUuid(*runtimeId)
        || *runtimeId == self_.runtimeId || !displayName || !isValidDisplayName(*displayName)
        || !commitment || !role || (*role != "peer" && roleName(*role) != "runtime-control")) {
        setError(error, "malformed pair.hello");
        return std::nullopt;
    }
    if (constantTimeEqual(peerRootSpki_, self_.rootSpki)) {
        setError(error, "a runtime cannot pair with itself");
        return std::nullopt;
    }
    if (const auto secret = textField(body, "invite")) {
        const auto granted = redeemInvite_ ? redeemInvite_(*secret) : std::nullopt;
        if (!granted) {
            setError(error, "the invite is unknown, used or expired");
            return std::nullopt;
        }
        invite_ = true;
        role_ = roleName(*granted) == "runtime-control" && roleName(*role) == "runtime-control"
            ? "runtime-control" : "peer";
    } else if (!windowOpen_) {
        setError(error, "pairing is closed");
        return std::nullopt;
    } else if (roleName(*role) == "runtime-control") {
        setError(error, "only a runtime-control invite grants Runtime Control");
        return std::nullopt;
    }
    peerRuntimeId_ = *runtimeId;
    peerDisplayName_ = *displayName;
    commitment_ = *commitment;
    nonce_ = randomBytes(kPairingNonceSize);
    return nlohmann::json{{"nonce", base64url(nonce_)}};
}

bool PairingResponder::onReveal(const nlohmann::json& body, std::string* error)
{
    const auto nonce = bytesField(body, "nonce", kPairingNonceSize);
    if (revealed_ || commitment_.empty() || !nonce || !pairingRevealMatches(commitment_, *nonce)) {
        setError(error, "the reveal does not match the commitment");
        rejected_ = true;
        return false;
    }
    revealed_ = true;
    code_ = pairingCode(peerRootSpki_, self_.rootSpki, *nonce, nonce_, exporter_);
    return true;
}

bool PairingResponder::onConfirm(const nlohmann::json& body, std::string* error)
{
    const auto key = bytesField(body, "announce_key", 32);
    if (!revealed_ || confirmed_ || !key) {
        setError(error, "unexpected or malformed pair.confirm");
        return false;
    }
    peerAnnounceKey_ = *key;
    confirmed_ = true;
    return true;
}

bool PairingResponder::ready() const
{
    return revealed_ && confirmed_ && !rejected_ && (approved_ || !needsApproval());
}

nlohmann::json PairingResponder::result() const
{
    if (!ready()) return {{"status", "rejected"}};
    return {{"status", "accepted"},
            {"runtime_id", self_.runtimeId},
            {"display_name", self_.displayName},
            {"announce_key", base64url(self_.announceKey)},
            {"role", role_}};
}

PairingOutcome PairingResponder::outcome() const
{
    return PairingOutcome{peerRuntimeId_, peerDisplayName_, peerRootSpki_, peerAnnounceKey_, role_};
}

} // namespace logos::peering
