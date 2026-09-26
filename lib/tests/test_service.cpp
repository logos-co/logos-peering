// Two peering services in one process, each with a real tls_tcp control
// endpoint on 127.0.0.1: pairing, gating, and a route from a facade to an
// exporting host.
#include "logos/peering/service.h"

#include "logos/peering/callers.h"
#include "logos/peering/certs.h"
#include "logos/peering/facade.h"
#include "logos/peering/identity.h"
#include "logos/peering/invites.h"

#include <logos_protocol.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
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
    explicit Runtime(const std::string& name, AccessDecision decide = {})
        : name(name), dir(freshDir(name)), decide(std::move(decide))
    {
        identity = std::make_shared<FakeIdentity>(dir / "identity");
        start();
    }

    void start()
    {
        PeeringService::Options options;
        options.stateDir = dir / "peering";
        options.identity = identity;
        options.decide = decide;
        options.tick = std::chrono::milliseconds(20);
        options.emit = [this](const std::string& event, const json& args) {
            std::lock_guard<std::mutex> lock(mutex);
            events.push_back({event, args});
        };
        service = std::make_unique<PeeringService>(std::move(options));
    }

    // The same state and identity, a new service: a runtime that restarted.
    void restart()
    {
        service.reset();
        start();
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
    AccessDecision decide;
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

// Stands in for A's facade: dials B's host with what requestRoute returned.
struct Dialer {
    Runtime& runtime;
    std::string import;
    Credential credential;
    json route;
    lp_client* client = nullptr;

    Dialer(Runtime& r, std::string name) : runtime(r), import(std::move(name))
    {
        EXPECT_TRUE(credential.obtain(runtime, import, "client"));
    }

    ~Dialer()
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
        lp_client_set_session_hook(client, &Dialer::dial, &Dialer::hello, this);
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
        const json& r = static_cast<Dialer*>(userData)->route;
        return heap(json{{"addresses", r["addresses"]}, {"port", r["port"]},
                         {"server_pin", r["server_pin"]}, {"anchors", r["anchors"]}}.dump());
    }

    static char* hello(const char*, void* userData)
    {
        auto* facade = static_cast<Dialer*>(userData);
        return heap(json{{"ticket", facade->route["ticket"]}, {"module", "echo_module"}}.dump());
    }
};

// A runtime's peering service as the provider its facades call, as themselves.
struct PeeringProvider {
    Runtime& runtime;
    lp_provider* provider = nullptr;

    PeeringProvider(Runtime& r, const std::string& name, const std::string& facade, const std::string& token)
        : runtime(r)
    {
        provider = lp_provider_create(name.c_str(), "[]");
        EXPECT_EQ(lp_provider_save_token(provider, facade.c_str(), token.c_str()), LP_OK);
        EXPECT_EQ(lp_provider_register(provider, &PeeringProvider::dispatch, &PeeringProvider::methods,
                                       nullptr, this), LP_OK);
        EXPECT_EQ(lp_token_save(name.c_str(), token.c_str()), LP_OK);
    }

    ~PeeringProvider() { lp_provider_destroy(provider); }

    static char* dispatch(const char* method, const char* args, void* userData)
    {
        auto* self = static_cast<PeeringProvider*>(userData);
        const auto caller = parseStrictObject(lp_current_caller_json());
        CallerRef ref;
        if (caller && caller->value("kind", "") == "module") ref = CallerRef::module(caller->value("name", ""));
        return heap(self->runtime.call(ref, method, json::parse(args ? args : "[]")).dump());
    }

    static char* methods(void*) { return heap("[]"); }
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

// B's core_service: an operator endpoint the runtime sets up as the host.
struct CoreServiceHost {
    Runtime& runtime;
    PKey key = generateP256();
    lp_provider* provider = nullptr;

    explicit CoreServiceHost(Runtime& r) : runtime(r)
    {
        provider = lp_provider_create("core_service", "[]");
        EXPECT_EQ(lp_provider_register(provider, &CoreServiceHost::dispatch, &CoreServiceHost::methods,
                                       nullptr, this), LP_OK);
        const json issued = runtime.engine("issueCertificate",
                                           json::array({"provider", makeCsrPem(key.get())}));
        EXPECT_TRUE(issued.contains("chain_pem")) << issued.dump();
        if (!issued.contains("chain_pem")) return;
        EXPECT_EQ(lp_provider_set_tls_credential(provider, issued["chain_pem"].get<std::string>().c_str(),
                                                 privateKeyPem(key.get()).c_str()), LP_OK);
        EXPECT_EQ(lp_provider_set_trust_anchors(provider, issued["anchors_pem"].get<std::string>().c_str()),
                  LP_OK);
        EXPECT_EQ(lp_provider_set_session_authenticator(provider, &CoreServiceHost::authenticate, this),
                  LP_OK);
        // Attached after registration, as the runtime does once peering is up.
        EXPECT_EQ(lp_provider_add_endpoint(provider, R"({"protocol":"tls_tcp","host":"127.0.0.1","port":0})"),
                  LP_OK);
        char* endpoints = lp_provider_endpoints_json(provider);
        const json noted = runtime.engine("noteEndpoints", json::array({json::parse(endpoints)}));
        lp_string_free(endpoints);
        EXPECT_TRUE(noted.value("ok", false)) << noted.dump();
    }

    ~CoreServiceHost() { lp_provider_destroy(provider); }

    // What the runtime does on anchorsChanged.
    void refreshAnchors()
    {
        const json reply = runtime.engine("sessionAnchors");
        EXPECT_EQ(lp_provider_set_trust_anchors(provider, reply.value("anchors_pem", "").c_str()), LP_OK);
    }

    static char* authenticate(const char* request, void* userData)
    {
        auto* host = static_cast<CoreServiceHost*>(userData);
        return heap(host->runtime.engine("redeemTicket", json::array({json::parse(request)})).dump());
    }

    static char* dispatch(const char* method, const char*, void*)
    {
        if (std::strcmp(method, "whoami") == 0) return heap(lp_current_caller_json());
        return nullptr;
    }

    static char* methods(void*) { return heap("[]"); }
};

// A runtime-less operator dialling the route operatorRoute gave it.
struct OperatorDial {
    PeeringService::OperatorRoute route;
    lp_client* client = nullptr;

    explicit OperatorDial(PeeringService::OperatorRoute r) : route(std::move(r)) {}
    ~OperatorDial()
    {
        if (client) lp_client_destroy(client);
    }

    int whoami(json* result)
    {
        client = lp_client_create("core_service", "logosctl", R"({"protocol":"tls_tcp"})", nullptr);
        lp_client_set_tls_credential(client, route.chainPem.c_str(), route.keyPem.c_str());
        lp_client_set_session_hook(client, &OperatorDial::dial, &OperatorDial::hello, this);
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
        return heap(static_cast<OperatorDial*>(userData)->route.dial.dump());
    }
    static char* hello(const char*, void* userData)
    {
        return heap(static_cast<OperatorDial*>(userData)->route.hello.dump());
    }
};

json operatorConfig()
{
    return {{"control", {{"enabled", true}, {"host", "127.0.0.1"}, {"port", 0}}},
            {"exports", {{"enabled", true}}},
            {"operator", true}};
}

// A redeems B's operator invite, and B approves it.
void pairAsOperator(Runtime& a, Runtime& b)
{
    const json invite = b.manage("createInvite", json::array({"operator", 600}));
    ASSERT_TRUE(invite.contains("invite")) << invite.dump();
    ASSERT_FALSE(a.manage("redeemInvite", json::array({invite["invite"]})).contains("error"));
    std::string id;
    ASSERT_TRUE(waitFor([&] {
        const json pending = b.manage("pending")["pending"];
        for (const auto& p : pending)
            if (p.value("direction", "") == "incoming" && p.value("needs_approval", false)) id = p["id"];
        return !id.empty();
    }));
    ASSERT_FALSE(b.manage("confirmPairing", json::array({id})).contains("error"));
    ASSERT_TRUE(waitFor([&] { return a.manage("peers")["peers"].size() == 1; }));
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
    // Local operators manage, the default `auto` included; remote ones only read.
    EXPECT_TRUE(b.call(CallerRef::named("auto"), "setExport", export1).value("ok", false));
    EXPECT_TRUE(b.call(CallerRef::named("auto"), "removeExport", json::array({"echo_module"}))
                    .value("ok", false));
    EXPECT_FALSE(b.call(CallerRef::named("@peer:x"), "peers").contains("error"));
    EXPECT_EQ(b.call(CallerRef::named("@peer:x"), "setExport", export1).value("error", ""),
              "NOT_AUTHORISED");
    EXPECT_EQ(b.call(CallerRef::named("@peer:x"), "createInvite", json::array({"peer", 60}))
                  .value("error", ""), "NOT_AUTHORISED");
    // Named operators and the shell manage.
    EXPECT_TRUE(b.call(CallerRef::named("alice"), "setExport", export1).value("ok", false));
    EXPECT_TRUE(b.manage("removeExport", json::array({"echo_module"})).value("ok", false));
    // The engine reads what it acts on.
    EXPECT_FALSE(b.engine("exports").contains("error"));
    EXPECT_FALSE(b.engine("imports").contains("error"));
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
    Dialer facade(a, "echo");

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
    Dialer facade(a, "echo");
    // Not an allowed caller of the import on A.
    EXPECT_EQ(facade.requestRoute("stranger").value("error", ""), "NOT_AUTHORISED");
    // Allowed on A, but B's policy does not list it.
    EXPECT_EQ(facade.requestRoute("miner").value("error", ""), "NOT_AUTHORISED");
    EXPECT_TRUE(facade.requestRoute("wallet").contains("ticket"));
}

TEST(PeeringService, APolicyMayNameEveryExport)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    EXPECT_TRUE(b.manage("setPolicy", json::array({{{a.id() + "/*", {"core_service"}}}})).contains("error"));
    ASSERT_TRUE(b.manage("setPolicy", json::array({{{a.id() + "/wallet", {"*"}}}})).value("ok", false));
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", json::object()})).value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet", "miner"});
    Dialer facade(a, "echo");
    EXPECT_TRUE(facade.requestRoute("wallet").contains("ticket"));
    EXPECT_EQ(facade.requestRoute("miner").value("error", ""), "NOT_AUTHORISED");
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
    Dialer facade(a, "echo");
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
    Dialer facade(a, "echo");
    ASSERT_TRUE(facade.requestRoute("wallet").contains("ticket"));
    ASSERT_TRUE(b.manage("removePeer", json::array({a.id()})).value("ok", false));
    EXPECT_TRUE(b.sawEvent("routesRevoked"));
    // The session a spent ticket would open is refused, and so is a new route.
    json who;
    EXPECT_NE(facade.connect("echo_module", &who), LP_OK);
    EXPECT_TRUE(facade.requestRoute("wallet").contains("error"));
}

namespace {

std::string importState(Runtime& a)
{
    const json states = a.engine("importStates");
    return states.contains("echo") ? states["echo"].value("state", "") : std::string();
}

// A local consumer of the facade, on the ordinary local transport.
json callFacade(Facade& facade, const std::string& consumer, const char* method)
{
    const std::string token = consumer + "-token";
    lp_provider_save_token(facade.provider(), consumer.c_str(), token.c_str());
    lp_token_save("echo", token.c_str());
    lp_client* client = lp_client_create("echo", consumer.c_str(), nullptr, nullptr);
    char* out = nullptr;
    char* err = nullptr;
    const int status = lp_invoke(client, method, "[]", 10000, &out, &err);
    json result = status == LP_OK && out ? json::parse(out) : json{{"lp_error", err ? err : "?"}};
    lp_string_free(out);
    lp_string_free(err);
    lp_client_destroy(client);
    return result;
}

FacadeOptions facadeOptions()
{
    FacadeOptions options;
    options.name = "echo";
    options.transportSet = "[]";
    options.credential = "facade-credential";
    options.peering = "peering_a";
    options.retry = std::chrono::milliseconds(100);
    return options;
}

} // namespace

TEST(Facade, ServesAnImportAsItsConsumers)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    PeeringProvider peering(a, "peering_a", "echo", "facade-token");
    Facade facade(facadeOptions());
    std::string error;
    ASSERT_TRUE(facade.start(error)) << error;
    ASSERT_TRUE(waitFor([&] { return importState(a) == "ready"; })) << importState(a);
    EXPECT_TRUE(a.sawEvent("importStateChanged"));

    const json who = callFacade(facade, "wallet", "whoami");
    EXPECT_EQ(who, json({{"kind", "remote"}, {"peer", a.id()}, {"name", "wallet"}}));
    facade.stop();
}

TEST(Facade, ACallerTheImportDoesNotAdmitGetsAnError)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    PeeringProvider peering(a, "peering_a", "echo", "facade-token");
    Facade facade(facadeOptions());
    std::string error;
    ASSERT_TRUE(facade.start(error)) << error;
    ASSERT_TRUE(waitFor([&] { return importState(a) == "ready"; }));

    const json refused = callFacade(facade, "stranger", "whoami");
    EXPECT_EQ(refused.value("code", ""), "dispatch_failed") << refused.dump();
    EXPECT_EQ(refused.value("origin", ""), "echo");
    facade.stop();
}

TEST(Facade, ReportsAnUnreachablePeer)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    importEcho(a, b, {"wallet"});
    // No host serves echo_module on B: no route, so the facade cannot publish.
    PeeringProvider peering(a, "peering_a", "echo", "facade-token");
    Facade facade(facadeOptions());
    std::string error;
    ASSERT_TRUE(facade.start(error)) << error;
    ASSERT_TRUE(waitFor([&] { return importState(a) == "error"; })) << importState(a);
    // B's one answer for it, not a network failure.
    const std::string reason = a.engine("importStates")["echo"].value("reason", "");
    EXPECT_NE(reason.find("grants no route"), std::string::npos) << reason;
    facade.stop();
}

namespace {

struct Received {
    std::mutex mutex;
    std::vector<std::pair<std::string, std::string>> events;
};

void onReceived(const char* name, const char* data, void* userData)
{
    auto* received = static_cast<Received*>(userData);
    std::lock_guard<std::mutex> lock(received->mutex);
    received->events.push_back({name ? name : "", data ? data : ""});
}

} // namespace

TEST(Facade, CarriesTheEventsAnExportShares)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", {{"events", true}}})).value("ok", false));
    ASSERT_TRUE(b.manage("setPolicy", json::array({{{a.id() + "/wallet", {"echo_module"}}}})).value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
    ExportHost host(b, "echo_module");
    const json rule = {{"from", b.id()}, {"module", "echo_module"}, {"allowed_callers", {"wallet"}},
                       {"events", true}};
    ASSERT_TRUE(a.manage("setImport", json::array({"echo", rule})).value("ok", false));
    ASSERT_TRUE(a.engine("facadeLoaded", json::array({"echo", 1})).value("ok", false));
    PeeringProvider peering(a, "peering_a", "echo", "facade-token");
    Facade facade(facadeOptions());
    std::string error;
    ASSERT_TRUE(facade.start(error)) << error;
    ASSERT_TRUE(waitFor([&] { return importState(a) == "ready"; }));

    lp_provider_save_token(facade.provider(), "wallet", "wallet-token");
    lp_token_save("echo", "wallet-token");
    lp_client* client = lp_client_create("echo", "wallet", nullptr, nullptr);
    Received received;
    lp_subscription* subscription = lp_subscribe(client, "tick", &onReceived, &received);
    ASSERT_NE(subscription, nullptr);
    const bool arrived = waitFor([&] {
        lp_provider_emit_event(host.provider, "tick", "[7]");
        std::lock_guard<std::mutex> lock(received.mutex);
        return !received.events.empty();
    });
    ASSERT_TRUE(arrived);
    {
        std::lock_guard<std::mutex> lock(received.mutex);
        EXPECT_EQ(received.events.front().first, "tick");
        EXPECT_EQ(json::parse(received.events.front().second), json::array({7}));
    }
    lp_unsubscribe(subscription);
    lp_client_destroy(client);
    facade.stop();
}

TEST(Facade, FollowsItsOwnSessionWithoutWaitingForTheHealthCheck)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    const json granted = {{a.id() + "/wallet", {"echo_module"}}};
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", {{"events", true}}})).value("ok", false));
    ASSERT_TRUE(b.manage("setPolicy", json::array({granted})).value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
    auto host = std::make_unique<ExportHost>(b, "echo_module");
    const json rule = {{"from", b.id()}, {"module", "echo_module"}, {"allowed_callers", {"wallet"}},
                       {"events", true}};
    ASSERT_TRUE(a.manage("setImport", json::array({"echo", rule})).value("ok", false));
    ASSERT_TRUE(a.engine("facadeLoaded", json::array({"echo", 1})).value("ok", false));
    PeeringProvider peering(a, "peering_a", "echo", "facade-token");
    Facade facade(facadeOptions());
    std::string error;
    ASSERT_TRUE(facade.start(error)) << error;
    ASSERT_TRUE(waitFor([&] { return importState(a) == "ready"; }));
    const auto reason = [&] { return a.engine("importStates")["echo"].value("reason", ""); };
    // Well inside the 15 s health interval.
    constexpr auto kPrompt = std::chrono::seconds(5);

    host.reset();
    EXPECT_TRUE(waitFor([&] { return importState(a) == "error"; }, kPrompt)) << importState(a);
    ASSERT_TRUE(b.manage("setPolicy", json::array({json::object()})).value("ok", false));
    EXPECT_TRUE(waitFor([&] { return reason().find("grants no route") != std::string::npos; }, kPrompt))
        << reason();

    ASSERT_TRUE(b.manage("setPolicy", json::array({granted})).value("ok", false));
    host = std::make_unique<ExportHost>(b, "echo_module");
    EXPECT_TRUE(waitFor([&] { return importState(a) == "ready"; }, kPrompt)) << reason();
    facade.stop();
}

namespace {

std::string readText(const fs::path& path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

json localInviteConfig(const fs::path& path, const std::string& host = "127.0.0.1")
{
    return {{"control", {{"enabled", true}, {"host", host}, {"port", 0},
                         {"local_invite", {{"path", path.string()}}}}},
            {"exports", {{"enabled", true}}}};
}

} // namespace

TEST(PeeringService, ALocalInvitePairsOverLoopbackAndIsReplaced)
{
    Runtime a("basecamp");
    Runtime b("daemon");
    a.configure();
    const fs::path path = b.dir / "link" / "local-invite";
    b.configure(localInviteConfig(path));
    ASSERT_TRUE(waitFor([&] { return fs::exists(path); }));
    const auto perms = fs::status(path).permissions();
    EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
    const std::string first = readText(path);
    ASSERT_EQ(first.rfind("logos-pair:v1:", 0), 0u) << first;

    const json started = a.manage("redeemInvite", json::array({first.substr(0, first.find('\n'))}));
    ASSERT_FALSE(started.contains("error")) << started.dump();
    ASSERT_TRUE(waitFor([&] { return a.manage("peers")["peers"].size() == 1 && b.manage("peers")["peers"].size() == 1; }));
    // Used once, then replaced.
    ASSERT_TRUE(waitFor([&] { return readText(path) != first && !readText(path).empty(); }));
}

TEST(PeeringService, ALocalInviteGrantsWhatItAllows)
{
    Runtime a("basecamp");
    Runtime b("daemon");
    a.configure();
    const fs::path path = b.dir / "local-invite";
    json config = localInviteConfig(path);
    config["control"]["local_invite"]["allow"] = {"*"};
    b.configure(config);
    ASSERT_TRUE(waitFor([&] { return fs::exists(path); }));
    const std::string text = readText(path);
    ASSERT_FALSE(a.manage("redeemInvite", json::array({text.substr(0, text.find('\n'))})).contains("error"));
    ASSERT_TRUE(waitFor([&] { return a.manage("peers")["peers"].size() == 1 && b.manage("peers")["peers"].size() == 1; }));
    EXPECT_EQ(b.engine("remotePolicy"), json({{a.id() + "/*", {"*"}}}));

    // Every export is A's to see and, from any of its consumers, to call.
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", json::object()})).value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
    const json offered = a.manage("peerExports", json::array({b.id()}));
    ASSERT_TRUE(offered.contains("exports")) << offered.dump();
    EXPECT_EQ(offered["exports"], json({{"echo_module", {{"events", false}, {"loaded", true}}}}));
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"*"});
    Dialer facade(a, "echo");
    EXPECT_TRUE(facade.requestRoute("any_ui").contains("ticket"));
}

TEST(PeeringService, PeerExportsIsForManagersOfEnrolledPeers)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    EXPECT_EQ(a.manage("peerExports", json::array({b.id()})).value("error", ""), "NO_SUCH_PEER");
    pairByInvite(a, b);
    // Pairing grants nothing: B offers A no export until its policy names one.
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", json::object()})).value("ok", false));
    EXPECT_EQ(a.manage("peerExports", json::array({b.id()}))["exports"], json::object());
    EXPECT_EQ(a.call(CallerRef::named("@peer:" + b.id()), "peerExports", json::array({b.id()}))
                  .value("error", ""), "NOT_AUTHORISED");
}

TEST(PeeringService, ALocalInviteIsNotRedeemedFromAnotherAddress)
{
#ifdef __APPLE__
    // Local Network privacy holds a dial to this host's own LAN address.
    GTEST_SKIP() << "macOS gates LAN dials behind the Local Network permission";
#endif
    const std::string lan = [] {
        // The same address guess invites use; none on a loopback-only host.
        Runtime probe("probe");
        probe.configure({{"control", {{"enabled", true}, {"host", "0.0.0.0"}, {"port", 0}}}});
        const json invite = probe.manage("createInvite", json::array({"peer", 60}));
        const auto parsed = invite.contains("invite")
            ? parseInvite(invite["invite"].get<std::string>()) : std::nullopt;
        return parsed ? parsed->host : std::string();
    }();
    if (lan.empty() || lan.rfind("127.", 0) == 0) GTEST_SKIP() << "no address but loopback here";
    Runtime a("stranger");
    Runtime b("daemon");
    a.configure();
    const fs::path path = b.dir / "local-invite";
    b.configure(localInviteConfig(path, "0.0.0.0"));
    ASSERT_TRUE(waitFor([&] { return fs::exists(path); }));
    auto invite = parseInvite(readText(path).substr(0, readText(path).find('\n')));
    ASSERT_TRUE(invite);
    invite->host = lan;
    const json started = a.manage("redeemInvite", json::array({formatInvite(*invite)}));
    EXPECT_TRUE(started.contains("error")) << started.dump();
    EXPECT_EQ(b.manage("peers")["peers"].size(), 0u);
}

TEST(PeeringService, AnOperatorReachesCoreServiceAsItsPeer)
{
    Runtime a("laptop");
    Runtime b("office");
    // Like logosctl: no endpoint of its own.
    a.configure({{"control", {{"enabled", false}}}, {"exports", {{"enabled", false}}}});
    b.configure(operatorConfig());
    CoreServiceHost core(b);
    pairAsOperator(a, b);
    core.refreshAnchors();
    EXPECT_EQ(a.manage("peers")["peers"][0]["granted_role"], "operator");
    EXPECT_EQ(b.manage("peers")["peers"][0]["role"], "operator");

    std::string error;
    const auto route = a.service->operatorRoute(b.id(), &error);
    ASSERT_TRUE(route.has_value()) << error;
    EXPECT_EQ(route->hello["module"], "core_service");
    json who;
    OperatorDial dial(*route);
    ASSERT_EQ(dial.whoami(&who), LP_OK);
    EXPECT_EQ(who, json({{"kind", "operator"}, {"name", "@peer:" + a.id()}}));
}

TEST(PeeringService, OnlyAnOperatorPairingGetsARouteToCoreService)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure(operatorConfig());
    CoreServiceHost core(b);
    pairByInvite(a, b);
    std::string error;
    EXPECT_FALSE(a.service->operatorRoute(b.id(), &error).has_value());
    EXPECT_EQ(error.rfind("NOT_AN_OPERATOR", 0), 0u) << error;
    EXPECT_FALSE(a.service->operatorRoute("nobody", &error).has_value());
    EXPECT_EQ(error, "NO_SUCH_PEER");
}

TEST(PeeringService, WithoutOperatorTheHostSpeaksForNoEndpoint)
{
    Runtime b("office");
    b.configure();
    const PKey key = generateP256();
    EXPECT_EQ(b.engine("issueCertificate", json::array({"provider", makeCsrPem(key.get())})).value("error", ""),
              "NOT_AUTHORISED");
    EXPECT_EQ(b.manage("createInvite", json::array({"operator", 600})).value("error", ""), "OPERATOR_DISABLED");
}

TEST(PeeringService, TheAuthorityDecidesRoutesAndANewPolicyEndsWhatItDenies)
{
    std::atomic<int> answer{1}; // 1 allow, 0 deny, -1 no answer
    Runtime a("laptop");
    Runtime b("office", [&](const std::string&, const std::string&, const std::string&) -> std::optional<bool> {
        if (answer < 0) return std::nullopt;
        return answer == 1;
    });
    a.configure();
    b.configure();
    pairByInvite(a, b);
    // No local policy: the authority alone lets the route through.
    ASSERT_TRUE(b.manage("setExport", json::array({"echo_module", json::object()})).value("ok", false));
    ASSERT_TRUE(b.engine("exportLoaded", json::array({"echo_module", 1})).value("ok", false));
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    Dialer facade(a, "echo");
    ASSERT_TRUE(facade.requestRoute("wallet").contains("ticket"));
    EXPECT_EQ(b.engine("reevaluateRoutes").value("revoked", -1), 0);

    answer = 0;
    EXPECT_EQ(b.engine("reevaluateRoutes").value("revoked", -1), 1);
    EXPECT_TRUE(b.sawEvent("routesRevoked"));
    EXPECT_TRUE(b.manage("routes")["served"].empty());
    EXPECT_EQ(facade.requestRoute("wallet").value("error", ""), "NOT_AUTHORISED");
    // No answer is no route.
    answer = -1;
    EXPECT_EQ(facade.requestRoute("wallet").value("error", ""), "NOT_AUTHORISED");
    EXPECT_EQ(b.call(CallerRef::module("shell"), "reevaluateRoutes").value("error", ""), "NOT_AUTHORISED");
}

TEST(PeeringService, AnEphemeralControlPortIsKeptAcrossARestart)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    const std::uint16_t first = b.port();
    ASSERT_NE(first, 0);
    pairByInvite(a, b);
    b.restart();
    b.configure();
    EXPECT_EQ(b.port(), first);
    // A still reaches B where it paired with it.
    EXPECT_TRUE(a.manage("peerExports", json::array({b.id()})).contains("exports"));
}

TEST(PeeringService, StatusSaysWhyTheControlEndpointIsNotListening)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    const json taken = {{"name", "office"},
                        {"shell", "shell"},
                        {"control", {{"enabled", true}, {"host", "127.0.0.1"}, {"port", a.port()}}}};
    const json refused = b.engine("configure", json::array({taken}));
    EXPECT_NE(refused.value("error", "").find("CONTROL_UNAVAILABLE"), std::string::npos) << refused.dump();
    const json down = b.manage("status")["control"];
    EXPECT_TRUE(down.value("enabled", false));
    EXPECT_EQ(down.value("port", -1), 0);
    EXPECT_NE(down.value("error", "").find("cannot listen on 127.0.0.1:"), std::string::npos) << down.dump();
    const json invite = b.manage("createInvite", json::array({"peer", 60}));
    EXPECT_NE(invite.value("error", "").find("CONTROL_UNAVAILABLE: cannot listen"), std::string::npos)
        << invite.dump();

    b.configure();
    const json up = b.manage("status")["control"];
    EXPECT_NE(up.value("port", 0), 0);
    EXPECT_FALSE(up.contains("error")) << up.dump();
}

TEST(PeeringService, ARenewalAsksAgainWhetherTheImportAdmitsTheConsumer)
{
    Runtime a("laptop");
    Runtime b("office");
    a.configure();
    b.configure();
    pairByInvite(a, b);
    exportEcho(b, a, "wallet");
    ExportHost host(b, "echo_module");
    importEcho(a, b, {"wallet"});
    Dialer facade(a, "echo");
    const json route = facade.requestRoute("wallet");
    ASSERT_TRUE(route.contains("route")) << route.dump();
    const auto renew = [&] {
        return a.call(CallerRef::module("echo"), "renewRoute", json::array({route["route"]}));
    };
    EXPECT_TRUE(renew().contains("lifetime_ms")) << renew().dump();
    // Narrowed: the consumer the route was issued for gets no renewal.
    const json narrowed = {{"from", b.id()}, {"module", "echo_module"}, {"allowed_callers", {"miner"}}};
    ASSERT_TRUE(a.manage("setImport", json::array({"echo", narrowed})).value("ok", false));
    EXPECT_EQ(renew().value("error", ""), "NOT_AUTHORISED");
}
