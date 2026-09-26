// Two peering services in one process, each with a real tls_tcp control
// endpoint on 127.0.0.1: pairing, gating, and a route from a facade to an
// exporting host.
#include "logos/peering/service.h"

#include "logos/peering/certs.h"
#include "logos/peering/identity.h"
#include "logos/peering/invites.h"

#include <logos_protocol.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <mutex>
#include <thread>

using namespace logos::peering;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

char* heap(const std::string& text)
{
    auto* out = static_cast<char*>(std::malloc(text.size() + 1));
    std::memcpy(out, text.c_str(), text.size() + 1);
    return out;
}

fs::path freshDir(const std::string& label)
{
    static std::atomic<int> counter{0};
    const fs::path dir = fs::temp_directory_path()
        / ("peering-" + label + "-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

class FakeIdentity : public IdentitySource {
public:
    explicit FakeIdentity(const fs::path& dir) : identity(*loadOrCreateIdentity(dir)) {}

    std::optional<Info> info(std::string*) override
    {
        return Info{identity.uuid, certPem(identity.rootCert.get()), identity.displayId()};
    }

    std::optional<std::string> issue(Role role, const Bytes& spki, std::chrono::seconds validity,
                                     std::string*) override
    {
        const Cert leaf = issueLeaf(identity.rootKey.get(), identity.rootCert.get(), role, spki, validity);
        return certPem(leaf.get());
    }

    RuntimeIdentity identity;
};

bool waitFor(const std::function<bool()>& condition, std::chrono::milliseconds limit = std::chrono::seconds(10))
{
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return condition();
}

struct Runtime {
    explicit Runtime(const std::string& name) : name(name), dir(freshDir(name))
    {
        identity = std::make_shared<FakeIdentity>(dir / "identity");
        PeeringService::Options options;
        options.stateDir = dir / "peering";
        options.identity = identity;
        options.tick = std::chrono::milliseconds(20);
        options.emit = [this](const std::string& event, const json& args) {
            std::lock_guard<std::mutex> lock(mutex);
            events.push_back({event, args});
        };
        service = std::make_unique<PeeringService>(std::move(options));
    }

    ~Runtime()
    {
        service.reset();
        fs::remove_all(dir);
    }

    json call(const CallerRef& caller, const std::string& method, json args = json::array())
    {
        return service->invoke(caller, method, args);
    }
    json manage(const std::string& method, json args = json::array())
    {
        return call(CallerRef::module("shell"), method, std::move(args));
    }
    json engine(const std::string& method, json args = json::array())
    {
        return call(CallerRef::host(), method, std::move(args));
    }

    void configure(json extra = json::object())
    {
        json config = {{"name", name},
                       {"shell", "shell"},
                       {"control", {{"enabled", true}, {"host", "127.0.0.1"}, {"port", 0}}},
                       {"exports", {{"enabled", true}}}};
        config.update(extra);
        const json reply = engine("configure", json::array({config}));
        ASSERT_TRUE(reply.value("ok", false)) << reply.dump();
    }

    std::string id() const { return identity->identity.uuid; }
    std::uint16_t port() const { return service->controlPort(); }

    bool sawEvent(const std::string& event)
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& [name, args] : events)
            if (name == event) return true;
        return false;
    }

    std::string name;
    fs::path dir;
    std::shared_ptr<FakeIdentity> identity;
    std::unique_ptr<PeeringService> service;
    std::mutex mutex;
    std::vector<std::pair<std::string, json>> events;
};

void pairByInvite(Runtime& a, Runtime& b)
{
    const json invite = b.manage("createInvite", json::array({"peer", 3600}));
    ASSERT_TRUE(invite.contains("invite")) << invite.dump();
    const json started = a.manage("redeemInvite", json::array({invite["invite"]}));
    ASSERT_FALSE(started.contains("error")) << started.dump();
    ASSERT_TRUE(waitFor([&] { return a.manage("peers")["peers"].size() == 1 && b.manage("peers")["peers"].size() == 1; }));
}

// A module host's key, certified by its runtime's peering service.
struct Credential {
    PKey key = generateP256();
    std::string chainPem;
    std::string anchorsPem;

    bool obtain(Runtime& runtime, const std::string& module, const std::string& role)
    {
        const json reply = runtime.call(CallerRef::module(module), "issueCertificate",
                                        json::array({role, makeCsrPem(key.get())}));
        if (!reply.contains("chain_pem")) {
            ADD_FAILURE() << reply.dump();
            return false;
        }
        chainPem = reply["chain_pem"].get<std::string>();
        anchorsPem = reply["anchors_pem"].get<std::string>();
        return true;
    }
    std::string keyPem() const { return privateKeyPem(key.get()); }
};

// B's host of an exported module: authenticates sessions through B's service.
struct ExportHost {
    Runtime& runtime;
    std::string module;
    Credential credential;
    lp_provider* provider = nullptr;

    ExportHost(Runtime& r, std::string name) : runtime(r), module(std::move(name))
    {
        EXPECT_TRUE(credential.obtain(runtime, module, "provider"));
        provider = lp_provider_create(module.c_str(),
                                      R"([{"protocol":"tls_tcp","host":"127.0.0.1","port":0}])");
        EXPECT_EQ(lp_provider_set_tls_credential(provider, credential.chainPem.c_str(),
                                                 credential.keyPem().c_str()), LP_OK);
        EXPECT_EQ(lp_provider_set_trust_anchors(provider, credential.anchorsPem.c_str()), LP_OK);
        EXPECT_EQ(lp_provider_set_session_authenticator(provider, &ExportHost::authenticate, this), LP_OK);
        EXPECT_EQ(lp_provider_register(provider, &ExportHost::dispatch, &ExportHost::methods, nullptr, this),
                  LP_OK);
        char* endpoints = lp_provider_endpoints_json(provider);
        const json reply = runtime.call(CallerRef::module(module), "noteEndpoints",
                                        json::array({json::parse(endpoints)}));
        lp_string_free(endpoints);
        EXPECT_TRUE(reply.value("ok", false)) << reply.dump();
    }

    ~ExportHost() { lp_provider_destroy(provider); }

    static char* authenticate(const char* request, void* userData)
    {
        auto* host = static_cast<ExportHost*>(userData);
        const json reply = host->runtime.call(CallerRef::module(host->module), "redeemTicket",
                                              json::array({json::parse(request)}));
        return heap(reply.dump());
    }

    static char* dispatch(const char* method, const char*, void*)
    {
        if (std::strcmp(method, "whoami") == 0) return heap(lp_current_caller_json());
        return nullptr;
    }

    static char* methods(void*) { return heap("[]"); }
};

// A's facade for an import: dials B's host with what requestRoute returned.
struct Facade {
    Runtime& runtime;
    std::string import;
    Credential credential;
    json route;
    lp_client* client = nullptr;

    Facade(Runtime& r, std::string name) : runtime(r), import(std::move(name))
    {
        EXPECT_TRUE(credential.obtain(runtime, import, "client"));
    }

    ~Facade()
    {
        if (client) lp_client_destroy(client);
    }

    json requestRoute(const std::string& consumer)
    {
        route = runtime.call(CallerRef::module(import), "requestRoute", json::array({consumer, 5000}));
        return route;
    }

    int connect(const std::string& target, json* result)
    {
        if (client) lp_client_destroy(client);
        client = lp_client_create(target.c_str(), import.c_str(), R"({"protocol":"tls_tcp"})", nullptr);
        lp_client_set_tls_credential(client, credential.chainPem.c_str(), credential.keyPem().c_str());
        lp_client_set_session_hook(client, &Facade::dial, &Facade::hello, this);
        char* out = nullptr;
        char* err = nullptr;
        const int status = lp_invoke(client, "whoami", "[]", 5000, &out, &err);
        if (out && result) *result = json::parse(out);
        lp_string_free(out);
        lp_string_free(err);
        return status;
    }

    static char* dial(const char*, void* userData)
    {
        const json& r = static_cast<Facade*>(userData)->route;
        return heap(json{{"addresses", r["addresses"]}, {"port", r["port"]},
                         {"server_pin", r["server_pin"]}, {"anchors", r["anchors"]}}.dump());
    }

    static char* hello(const char*, void* userData)
    {
        auto* facade = static_cast<Facade*>(userData);
        return heap(json{{"ticket", facade->route["ticket"]}, {"module", "echo_module"}}.dump());
    }
};

void exportEcho(Runtime& b, Runtime& a, const std::string& consumer)
{
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", json::object()})).value("ok", false));
    ASSERT_TRUE(b.manage("setPolicy", json::array({{{a.id() + "/" + consumer, {"echo_module"}}}}))
                    .value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
}

void importEcho(Runtime& a, Runtime& b, const std::vector<std::string>& allowed)
{
    const json rule = {{"from", b.id()}, {"module", "echo_module"}, {"allowed_callers", allowed}};
    ASSERT_TRUE(a.manage("setImport", json::array({"echo", rule})).value("ok", false));
    ASSERT_TRUE(a.engine("facadeLoaded", json::array({"echo", 1})).value("ok", false));
}

} // namespace

TEST(PeeringService, AnInviteEnrollsBothSides)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    const json aPeers = a.manage("peers")["peers"];
    const json bPeers = b.manage("peers")["peers"];
    EXPECT_EQ(aPeers[0]["runtime_id"], b.id());
    EXPECT_EQ(aPeers[0]["display_name"], "office");
    EXPECT_EQ(aPeers[0]["granted_role"], "peer");
    EXPECT_EQ(aPeers[0]["control_port"], b.port());
    EXPECT_EQ(bPeers[0]["runtime_id"], a.id());
    EXPECT_EQ(bPeers[0]["role"], "peer");
    EXPECT_EQ(bPeers[0]["control_port"], a.port());
    EXPECT_EQ(bPeers[0]["addresses"], json::array({"127.0.0.1"}));
    EXPECT_TRUE(a.sawEvent("peersChanged"));
    EXPECT_TRUE(b.sawEvent("peersChanged"));
    // Single use.
    EXPECT_EQ(b.manage("status")["invites"], 0);
}

TEST(PeeringService, ACodePairingWaitsForBothSides)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    ASSERT_FALSE(b.manage("openPairingWindow", json::array({60})).contains("error"));
    const json started = a.manage("pairWith", json::array({"127.0.0.1", b.port()}));
    ASSERT_TRUE(started.contains("id")) << started.dump();
    const std::string code = started["code"].get<std::string>();
    EXPECT_EQ(code.size(), 6u);

    json incoming;
    ASSERT_TRUE(waitFor([&] {
        incoming = b.manage("pending")["pending"];
        return incoming.size() == 1;
    }));
    EXPECT_EQ(incoming[0]["code"], code);
    EXPECT_EQ(incoming[0]["direction"], "incoming");
    EXPECT_EQ(incoming[0]["peer_runtime_id"], a.id());
    EXPECT_TRUE(b.sawEvent("pairingRequested"));

    ASSERT_TRUE(a.manage("confirmPairing", json::array({started["id"]})).value("ok", false));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(b.manage("peers")["peers"].size(), 0u);
    EXPECT_EQ(a.manage("peers")["peers"].size(), 0u);

    ASSERT_TRUE(b.manage("confirmPairing", json::array({incoming[0]["id"]})).value("ok", false));
    ASSERT_TRUE(waitFor([&] { return a.manage("peers")["peers"].size() == 1 && b.manage("peers")["peers"].size() == 1; }));
}

TEST(PeeringService, ARejectedPairingEnrollsNobody)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    b.manage("openPairingWindow", json::array({60}));
    const json started = a.manage("pairWith", json::array({"127.0.0.1", b.port()}));
    ASSERT_TRUE(started.contains("id")) << started.dump();
    json incoming;
    ASSERT_TRUE(waitFor([&] {
        incoming = b.manage("pending")["pending"];
        return incoming.size() == 1;
    }));
    a.manage("confirmPairing", json::array({started["id"]}));
    b.manage("rejectPairing", json::array({incoming[0]["id"]}));
    ASSERT_TRUE(waitFor([&] {
        const json pending = a.manage("pending")["pending"];
        return pending.size() == 1 && pending[0]["state"] == "failed";
    }));
    EXPECT_EQ(a.manage("peers")["peers"].size(), 0u);
    EXPECT_EQ(b.manage("peers")["peers"].size(), 0u);
}

TEST(PeeringService, PairingIsClosedWithoutAWindowOrAnInvite)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    const json started = a.manage("pairWith", json::array({"127.0.0.1", b.port()}));
    EXPECT_TRUE(started.contains("error"));
    EXPECT_EQ(b.manage("pending")["pending"].size(), 0u);
}

TEST(PeeringService, AnInviteNamingAnotherRootIsRefused)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    const json created = b.manage("createInvite", json::array({"peer", 3600}));
    auto invite = parseInvite(created["invite"].get<std::string>());
    ASSERT_TRUE(invite);
    const RuntimeIdentity other = *loadOrCreateIdentity(freshDir("other"));
    invite->rootDigest = base64url(sha256(other.rootSpki()));
    const json started = a.manage("redeemInvite", json::array({formatInvite(*invite)}));
    ASSERT_TRUE(started.contains("error"));
    EXPECT_NE(started["error"].get<std::string>().find("invite names"), std::string::npos);
    EXPECT_EQ(b.manage("peers")["peers"].size(), 0u);
}

TEST(PeeringService, CallersAreGated)
{
    Runtime b("office");
    b.configure();
    const json export1 = json::array({"echo_module", json::object()});
    EXPECT_EQ(b.call(CallerRef::module("stranger"), "status").value("error", ""), "NOT_AUTHORISED");
    EXPECT_EQ(b.call(CallerRef::module("stranger"), "setExport", export1).value("error", ""),
              "NOT_AUTHORISED");
    // auto and remote operators read, never write.
    EXPECT_FALSE(b.call(CallerRef::named("auto"), "status").contains("error"));
    EXPECT_EQ(b.call(CallerRef::named("auto"), "setExport", export1).value("error", ""), "NOT_AUTHORISED");
    EXPECT_FALSE(b.call(CallerRef::named("@peer:x"), "peers").contains("error"));
    EXPECT_EQ(b.call(CallerRef::named("@peer:x"), "createInvite", json::array({"peer", 60}))
                  .value("error", ""), "NOT_AUTHORISED");
    // Named operators and the shell manage.
    EXPECT_TRUE(b.call(CallerRef::named("alice"), "setExport", export1).value("ok", false));
    EXPECT_TRUE(b.manage("removeExport", json::array({"echo_module"})).value("ok", false));
    // Engine methods belong to the runtime alone.
    EXPECT_EQ(b.manage("configure", json::array({json::object()})).value("error", ""), "NOT_AUTHORISED");
    EXPECT_EQ(b.call(CallerRef::module("echo_module"), "exportLoaded", json::array({"echo_module", 1}))
                  .value("error", ""), "NOT_AUTHORISED");
    // Host methods need a loaded export or facade.
    EXPECT_EQ(b.call(CallerRef::module("echo_module"), "sessionAnchors").value("error", ""),
              "NOT_AUTHORISED");
    EXPECT_EQ(b.manage("noSuchMethod").value("error", ""), "NO_SUCH_METHOD");
}

TEST(PeeringService, AFacadeReachesAnExportedModuleAsItsConsumer)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    Facade facade(a, "echo");

    const json route = facade.requestRoute("wallet");
    ASSERT_TRUE(route.contains("ticket")) << route.dump();
    EXPECT_EQ(route["addresses"], json::array({"127.0.0.1"}));
    json who;
    ASSERT_EQ(facade.connect("echo_module", &who), LP_OK);
    EXPECT_EQ(who, json({{"kind", "remote"}, {"peer", a.id()}, {"name", "wallet"}}));

    // The ticket was spent by that connection.
    json again;
    EXPECT_NE(facade.connect("echo_module", &again), LP_OK);
}

TEST(PeeringService, RoutesAreOnlyForListedConsumers)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet", "miner"});
    Facade facade(a, "echo");
    // Not an allowed caller of the import on A.
    EXPECT_EQ(facade.requestRoute("stranger").value("error", ""), "NOT_AUTHORISED");
    // Allowed on A, but B's policy does not list it.
    EXPECT_EQ(facade.requestRoute("miner").value("error", ""), "NOT_AUTHORISED");
    EXPECT_TRUE(facade.requestRoute("wallet").contains("ticket"));
}

TEST(PeeringService, AnUnloadedExportGetsNoRoute)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    importEcho(a, b, {"wallet"});
    Facade facade(a, "echo");
    // Loaded but no host has reported its endpoint.
    EXPECT_EQ(facade.requestRoute("wallet").value("error", ""), "NOT_AUTHORISED");
    {
        ExportHost host(b, "echo_module");
        EXPECT_TRUE(facade.requestRoute("wallet").contains("ticket"));
    }
    b.engine("exportExited", json::array({"echo_module", 1}));
    EXPECT_EQ(facade.requestRoute("wallet").value("error", ""), "NOT_AUTHORISED");
}

TEST(PeeringService, RemovingAPeerRevokesItsRoutes)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    Facade facade(a, "echo");
    ASSERT_TRUE(facade.requestRoute("wallet").contains("ticket"));
    ASSERT_TRUE(b.manage("removePeer", json::array({a.id()})).value("ok", false));
    EXPECT_TRUE(b.sawEvent("routesRevoked"));
    // The session a spent ticket would open is refused, and so is a new route.
    json who;
    EXPECT_NE(facade.connect("echo_module", &who), LP_OK);
    EXPECT_TRUE(facade.requestRoute("wallet").contains("error"));
}
