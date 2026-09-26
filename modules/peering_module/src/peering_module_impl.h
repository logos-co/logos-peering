#pragma once

// peering_module: links this runtime with others. Every method forwards to
// libpeering's PeeringService with its caller; the service gates it.
// Contract: docs/api.md.

#include <cstdint>
#include <memory>
#include <string>

#include <logos_json.h>
#include <logos_module_context.h>

namespace logos::peering {
class PeeringService;
}

class PeeringModuleImpl : public LogosModuleContext {
public:
    PeeringModuleImpl();
    ~PeeringModuleImpl() override;

    LogosMap configure(const LogosMap& config);
    LogosMap exportLoaded(const std::string& module, int64_t epoch);
    LogosMap exportExited(const std::string& module, int64_t epoch);
    LogosMap facadeLoaded(const std::string& name, int64_t epoch);
    LogosMap facadeExited(const std::string& name, int64_t epoch);
    LogosMap imports();
    LogosMap importStates();
    LogosMap remotePolicy();

    LogosMap issueCertificate(const std::string& role, const std::string& csrPem);
    LogosMap sessionAnchors();
    LogosMap redeemTicket(const LogosMap& request);
    LogosMap noteEndpoints(const LogosList& endpoints);
    LogosMap sessionState();

    LogosMap requestRoute(const std::string& consumer, int64_t timeoutMs);
    LogosMap renewRoute(const std::string& route);
    LogosMap importDescriptor();
    LogosMap reportImportState(const std::string& state, const std::string& reason);

    LogosMap status();
    LogosMap peers();
    LogosMap nearby();
    LogosMap pending();
    LogosMap routes();
    LogosMap exports();
    LogosMap openPairingWindow(int64_t seconds);
    LogosMap pairWith(const std::string& host, int64_t port);
    LogosMap confirmPairing(const std::string& id);
    LogosMap rejectPairing(const std::string& id);
    LogosMap createInvite(const std::string& role, int64_t ttlSeconds);
    LogosMap redeemInvite(const std::string& invite);
    LogosMap removePeer(const std::string& peer);
    LogosMap renamePeer(const std::string& peer, const std::string& alias);
    LogosMap setExport(const std::string& module, const LogosMap& config);
    LogosMap removeExport(const std::string& module);
    LogosMap setImport(const std::string& name, const LogosMap& config);
    LogosMap removeImport(const std::string& name);
    LogosMap setPolicy(const LogosMap& policy);

logos_events:
    void importsChanged();
    void importStateChanged(const std::string& name, const std::string& state, const std::string& reason);
    void remotePolicyChanged();
    void anchorsChanged();
    void routesRevoked(const std::string& peer, int64_t generation);
    void routeRenewed(const std::string& route, int64_t lifetimeMs);
    void peersChanged();
    void pairingRequested(const LogosMap& pending);
    void nearbyChanged();

protected:
    void onContextReady() override;
    LogosShutdown aboutToUnload() override;

private:
    LogosMap forward(const std::string& method, const LogosList& args);
    void emitEvent(const std::string& event, const LogosList& args);

    std::shared_ptr<logos::peering::PeeringService> m_service;
    std::string m_startError = "not started";
};
