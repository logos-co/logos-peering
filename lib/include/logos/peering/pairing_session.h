#pragma once

// The pairing exchange, independent of sockets. The initiator dials; both sides
// feed in what TLS proved (the peer's root SPKI and the connection's exporter).
//
//   A -> B  pair.hello   {v, runtime_id, display_name, commitment, role, invite?}
//   B -> A  pair.nonce   {nonce}
//   A -> B  pair.reveal  {nonce}
//   A -> B  pair.confirm {announce_key}        once A's user accepts the code
//   B -> A  pair.result  {status, runtime_id, display_name, announce_key?}
//
// A peer invite needs no code comparison on either side. An operator invite
// still needs B's approval, which shows the redeemer's display ID.

#include "logos/peering/crypto.h"

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace logos::peering {

struct PairingParty {
    std::string runtimeId;
    Bytes rootSpki;
    std::string displayName;
    Bytes announceKey;
};

struct PairingOutcome {
    std::string peerRuntimeId;
    std::string peerDisplayName;
    Bytes peerRootSpki;
    Bytes peerAnnounceKey;
    std::string role; // what the initiator was granted: peer | operator
};

class PairingInitiator {
public:
    PairingInitiator(PairingParty self, std::optional<std::string> inviteSecret,
                     std::string requestedRole = "peer");

    nlohmann::json hello() const;
    void setTransport(Bytes responderRootSpki, Bytes exporter);
    std::optional<nlohmann::json> onNonce(const nlohmann::json& body, std::string* error = nullptr);
    const std::string& code() const { return code_; }
    bool needsConfirmation() const { return !invite_; }
    nlohmann::json confirm() const;
    std::optional<PairingOutcome> onResult(const nlohmann::json& body, std::string* error = nullptr);

private:
    PairingParty self_;
    std::optional<std::string> invite_;
    std::string role_;
    Bytes nonce_;
    Bytes peerRootSpki_;
    Bytes exporter_;
    std::string code_;
    bool revealed_ = false;
};

class PairingResponder {
public:
    // Consumes an invite secret and returns the role it grants, or nothing.
    using RedeemInvite = std::function<std::optional<std::string>(const std::string& secret)>;

    PairingResponder(PairingParty self, RedeemInvite redeemInvite, bool pairingWindowOpen);

    void setTransport(Bytes initiatorRootSpki, Bytes exporter);
    std::optional<nlohmann::json> onHello(const nlohmann::json& body, std::string* error = nullptr);
    bool onReveal(const nlohmann::json& body, std::string* error = nullptr);
    bool onConfirm(const nlohmann::json& body, std::string* error = nullptr);
    void approve() { approved_ = true; }
    void reject() { rejected_ = true; }

    bool needsApproval() const { return !invite_ || role_ == "operator"; }
    bool rejected() const { return rejected_; }
    bool revealed() const { return revealed_; }
    bool confirmed() const { return confirmed_; }
    // Both sides agreed: send result() and enroll outcome().
    bool ready() const;
    nlohmann::json result() const;
    PairingOutcome outcome() const;

    const std::string& code() const { return code_; }
    const std::string& initiatorRuntimeId() const { return peerRuntimeId_; }
    const std::string& initiatorDisplayName() const { return peerDisplayName_; }
    const std::string& grantedRole() const { return role_; }

private:
    PairingParty self_;
    RedeemInvite redeemInvite_;
    bool windowOpen_;
    bool invite_ = false;
    std::string role_ = "peer";
    std::string peerRuntimeId_;
    std::string peerDisplayName_;
    Bytes commitment_;
    Bytes nonce_;
    Bytes peerRootSpki_;
    Bytes exporter_;
    Bytes peerAnnounceKey_;
    std::string code_;
    bool revealed_ = false;
    bool confirmed_ = false;
    bool approved_ = false;
    bool rejected_ = false;
};

} // namespace logos::peering
