#pragma once

// peering_identity: the runtime's UUID and root key. It certifies leaves for
// peering_module alone and has no network code. Contract: docs/api.md.

#include <cstdint>
#include <memory>
#include <string>

#include <logos_json.h>
#include <logos_module_context.h>

class PeeringIdentityImpl : public LogosModuleContext {
public:
    PeeringIdentityImpl();
    ~PeeringIdentityImpl() override;

    LogosMap runtimeId();
    LogosMap rootCertificate();
    LogosMap displayId();
    LogosMap issue(const std::string& role, const std::string& spki, int64_t validitySeconds);

protected:
    void onContextReady() override;

private:
    struct State;
    std::unique_ptr<State> m_state;
};
