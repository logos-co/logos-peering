#pragma once

// peering_module's behaviour, Qt-free: pairing, enrollments, exports and
// imports, route tickets, and the control endpoint (peering_control) other
// runtimes call over tls_tcp. The module forwards each method here with its
// caller; tests drive it directly. Contract: docs/api.md.

#include "logos/peering/certs.h"
#include "logos/peering/crypto.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

// Who called, as the runtime reported it.
struct CallerRef {
    enum class Kind { Unknown, Host, Module, Operator, Remote };
    Kind kind = Kind::Unknown;
    std::string name;
    std::string peer;

    static CallerRef host() { return {Kind::Host, {}, {}}; }
    static CallerRef module(std::string name) { return {Kind::Module, std::move(name), {}}; }
    static CallerRef named(std::string name) { return {Kind::Operator, std::move(name), {}}; }
};

// peering_identity, as peering_module reaches it.
class IdentitySource {
public:
    struct Info {
        std::string runtimeId;
        std::string rootCertPem;
        std::string displayId;
    };

    virtual ~IdentitySource() = default;
    virtual std::optional<Info> info(std::string* error) = 0;
    // A leaf for `spki` marked with `role`, PEM.
    virtual std::optional<std::string> issue(Role role, const Bytes& spki,
                                             std::chrono::seconds validity, std::string* error) = 0;
};

// Whether `consumer` on runtime `peer` may reach `target` here; nothing when
// the decision could not be made (the route is then refused).
using AccessDecision = std::function<std::optional<bool>(
    const std::string& peer, const std::string& consumer, const std::string& target)>;

class PeeringService {
public:
    struct Options {
        std::filesystem::path stateDir;
        std::shared_ptr<IdentitySource> identity;
        // Events of peering_module's own provider: name and argument array.
        std::function<void(const std::string&, const nlohmann::json&)> emit;
        // Unset: the local policy document decides.
        AccessDecision decide;
        std::chrono::milliseconds tick{1000};
    };

    explicit PeeringService(Options options);
    ~PeeringService();
    PeeringService(const PeeringService&) = delete;
    PeeringService& operator=(const PeeringService&) = delete;

    // One module method with its arguments (a JSON array). The result, or
    // {"error": "..."}. Never throws.
    nlohmann::json invoke(const CallerRef& caller, const std::string& method,
                          const nlohmann::json& args);

    // The control endpoint's bound port, 0 without one.
    std::uint16_t controlPort() const;

    // Remote Runtime Control from a tool with no runtime (logosctl --remote): how to
    // reach `peer`'s `logos_runtime_control` endpoint as this runtime's module instance
    // `consumer`, and a client credential made for it alone. `peer` must have enrolled
    // this runtime for runtime-control; its policy then decides each call.
    struct RuntimeControlSession {
        nlohmann::json dial;  // the tls_tcp dial hook's answer
        nlohmann::json hello; // the Hello to send after the handshake
        std::string chainPem;
        std::string keyPem;
        std::int64_t lifetimeMs = 0;
    };
    std::optional<RuntimeControlSession> runtimeControlSession(const std::string& peer, const std::string& consumer,
                                                               std::string* error = nullptr);

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

} // namespace logos::peering
