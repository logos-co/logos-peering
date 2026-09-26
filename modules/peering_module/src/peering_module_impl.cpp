#include "peering_module_impl.h"

#include "logos_sdk.h"

#include "logos/peering/service.h"

#include <logos_caller.h>

#include <atomic>
#include <filesystem>

using namespace logos::peering;

namespace {

LogosMap fault(const std::string& code) { return LogosMap{{"error", code}}; }

CallerRef callerRef()
{
    const logos::LogosCaller& caller = logos::currentCaller();
    switch (caller.kind) {
    case logos::CallerKind::Host:
        return CallerRef::host();
    case logos::CallerKind::Module:
        return CallerRef::module(caller.name);
    case logos::CallerKind::Operator:
        return CallerRef::named(caller.name);
    default:
        return CallerRef{};
    }
}

std::string textOf(const LogosMap& reply, const char* key)
{
    const auto it = reply.find(key);
    return it != reply.end() && it->is_string() ? it->get<std::string>() : std::string();
}

// peering_identity, through the typed client the dependency generates.
class ModuleIdentity final : public IdentitySource {
public:
    explicit ModuleIdentity(LogosModules& modules) : m_modules(modules) {}

    std::optional<Info> info(std::string* error) override
    {
        auto& identity = m_modules.peering_identity;
        const LogosMap id = identity.runtimeId();
        const LogosMap root = identity.rootCertificate();
        const LogosMap display = identity.displayId();
        Info out{textOf(id, "runtime_id"), textOf(root, "root_pem"), textOf(display, "display_id")};
        if (out.runtimeId.empty() || out.rootCertPem.empty()) {
            if (error) {
                *error = textOf(id, "error");
                if (error->empty()) *error = "peering_identity did not answer";
            }
            return std::nullopt;
        }
        return out;
    }

    std::optional<std::string> issue(Role role, const Bytes& spki, std::chrono::seconds validity,
                                     std::string* error) override
    {
        const LogosMap reply = m_modules.peering_identity.issue(roleName(role), base64url(spki),
                                                                validity.count());
        const std::string leaf = textOf(reply, "leaf_pem");
        if (leaf.empty()) {
            if (error) {
                *error = textOf(reply, "error");
                if (error->empty()) *error = "peering_identity did not answer";
            }
            return std::nullopt;
        }
        return leaf;
    }

private:
    LogosModules& m_modules;
};

} // namespace

PeeringModuleImpl::PeeringModuleImpl() = default;

PeeringModuleImpl::~PeeringModuleImpl() { std::atomic_store(&m_service, {}); }

void PeeringModuleImpl::onContextReady()
{
    if (instancePersistencePath().empty()) {
        m_startError = "no persistence path";
        return;
    }
    PeeringService::Options options;
    options.stateDir = std::filesystem::u8path(instancePersistencePath()) / "peering";
    options.identity = std::make_shared<ModuleIdentity>(modules());
    options.emit = [this](const std::string& event, const nlohmann::json& args) { emitEvent(event, args); };
    try {
        std::atomic_store(&m_service, std::make_shared<PeeringService>(std::move(options)));
    } catch (const std::exception& ex) {
        m_startError = ex.what();
    }
}

LogosShutdown PeeringModuleImpl::aboutToUnload()
{
    // Closes the control endpoint and every link before the image goes.
    std::atomic_store(&m_service, {});
    return LogosShutdown::Synchronous;
}

LogosMap PeeringModuleImpl::forward(const std::string& method, const LogosList& args)
{
    const auto service = std::atomic_load(&m_service);
    if (!service) return fault("UNAVAILABLE: " + m_startError);
    return service->invoke(callerRef(), method, args);
}

void PeeringModuleImpl::emitEvent(const std::string& event, const LogosList& args)
{
    const auto text = [&](std::size_t i) {
        return args.size() > i && args[i].is_string() ? args[i].get<std::string>() : std::string();
    };
    const auto number = [&](std::size_t i) {
        return args.size() > i && args[i].is_number_integer() ? args[i].get<int64_t>() : int64_t(0);
    };
    if (event == "importsChanged") importsChanged();
    else if (event == "exportsChanged") exportsChanged();
    else if (event == "importStateChanged") importStateChanged(text(0), text(1), text(2));
    else if (event == "remotePolicyChanged") remotePolicyChanged();
    else if (event == "anchorsChanged") anchorsChanged();
    else if (event == "routesRevoked") routesRevoked(text(0), number(1));
    else if (event == "routeRenewed") routeRenewed(text(0), number(1));
    else if (event == "peersChanged") peersChanged();
    else if (event == "pairingRequested")
        pairingRequested(args.size() > 0 && args[0].is_object() ? args[0] : LogosMap::object());
    else if (event == "nearbyChanged") nearbyChanged();
}

LogosMap PeeringModuleImpl::configure(const LogosMap& config)
{
    return forward("configure", LogosList::array({config}));
}
LogosMap PeeringModuleImpl::exportLoaded(const std::string& module, int64_t epoch)
{
    return forward("exportLoaded", LogosList::array({module, epoch}));
}
LogosMap PeeringModuleImpl::exportExited(const std::string& module, int64_t epoch)
{
    return forward("exportExited", LogosList::array({module, epoch}));
}
LogosMap PeeringModuleImpl::facadeLoaded(const std::string& name, int64_t epoch)
{
    return forward("facadeLoaded", LogosList::array({name, epoch}));
}
LogosMap PeeringModuleImpl::facadeExited(const std::string& name, int64_t epoch)
{
    return forward("facadeExited", LogosList::array({name, epoch}));
}
LogosMap PeeringModuleImpl::imports() { return forward("imports", LogosList::array()); }
LogosMap PeeringModuleImpl::importStates() { return forward("importStates", LogosList::array()); }
LogosMap PeeringModuleImpl::remotePolicy() { return forward("remotePolicy", LogosList::array()); }

LogosMap PeeringModuleImpl::issueCertificate(const std::string& role, const std::string& csrPem)
{
    return forward("issueCertificate", LogosList::array({role, csrPem}));
}
LogosMap PeeringModuleImpl::sessionAnchors() { return forward("sessionAnchors", LogosList::array()); }
LogosMap PeeringModuleImpl::redeemTicket(const LogosMap& request)
{
    return forward("redeemTicket", LogosList::array({request}));
}
LogosMap PeeringModuleImpl::noteEndpoints(const LogosList& endpoints)
{
    return forward("noteEndpoints", LogosList::array({endpoints}));
}
LogosMap PeeringModuleImpl::sessionState() { return forward("sessionState", LogosList::array()); }

LogosMap PeeringModuleImpl::requestRoute(const std::string& consumer, int64_t timeoutMs)
{
    return forward("requestRoute", LogosList::array({consumer, timeoutMs}));
}
LogosMap PeeringModuleImpl::renewRoute(const std::string& route)
{
    return forward("renewRoute", LogosList::array({route}));
}
LogosMap PeeringModuleImpl::importDescriptor() { return forward("importDescriptor", LogosList::array()); }
LogosMap PeeringModuleImpl::reportImportState(const std::string& state, const std::string& reason)
{
    return forward("reportImportState", LogosList::array({state, reason}));
}

LogosMap PeeringModuleImpl::status() { return forward("status", LogosList::array()); }
LogosMap PeeringModuleImpl::peers() { return forward("peers", LogosList::array()); }
LogosMap PeeringModuleImpl::nearby() { return forward("nearby", LogosList::array()); }
LogosMap PeeringModuleImpl::pending() { return forward("pending", LogosList::array()); }
LogosMap PeeringModuleImpl::routes() { return forward("routes", LogosList::array()); }
LogosMap PeeringModuleImpl::exports() { return forward("exports", LogosList::array()); }
LogosMap PeeringModuleImpl::openPairingWindow(int64_t seconds)
{
    return forward("openPairingWindow", LogosList::array({seconds}));
}
LogosMap PeeringModuleImpl::pairWith(const std::string& host, int64_t port)
{
    return forward("pairWith", LogosList::array({host, port}));
}
LogosMap PeeringModuleImpl::confirmPairing(const std::string& id)
{
    return forward("confirmPairing", LogosList::array({id}));
}
LogosMap PeeringModuleImpl::rejectPairing(const std::string& id)
{
    return forward("rejectPairing", LogosList::array({id}));
}
LogosMap PeeringModuleImpl::createInvite(const std::string& role, int64_t ttlSeconds)
{
    return forward("createInvite", LogosList::array({role, ttlSeconds}));
}
LogosMap PeeringModuleImpl::redeemInvite(const std::string& invite)
{
    return forward("redeemInvite", LogosList::array({invite}));
}
LogosMap PeeringModuleImpl::removePeer(const std::string& peer)
{
    return forward("removePeer", LogosList::array({peer}));
}
LogosMap PeeringModuleImpl::renamePeer(const std::string& peer, const std::string& alias)
{
    return forward("renamePeer", LogosList::array({peer, alias}));
}
LogosMap PeeringModuleImpl::setExport(const std::string& module, const LogosMap& config)
{
    return forward("setExport", LogosList::array({module, config}));
}
LogosMap PeeringModuleImpl::removeExport(const std::string& module)
{
    return forward("removeExport", LogosList::array({module}));
}
LogosMap PeeringModuleImpl::setImport(const std::string& name, const LogosMap& config)
{
    return forward("setImport", LogosList::array({name, config}));
}
LogosMap PeeringModuleImpl::removeImport(const std::string& name)
{
    return forward("removeImport", LogosList::array({name}));
}
LogosMap PeeringModuleImpl::setPolicy(const LogosMap& policy)
{
    return forward("setPolicy", LogosList::array({policy}));
}
