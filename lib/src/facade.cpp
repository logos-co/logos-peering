#include "logos/peering/facade.h"

#include "logos/peering/callers.h"
#include "logos/peering/crypto.h"

#include <logos_protocol.h>

#include <nlohmann/json.hpp>

#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

namespace logos::peering {
namespace {

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

constexpr int kPeeringTimeoutMs = 15000;
constexpr auto kHealthInterval = std::chrono::seconds(15);

char* heapCopy(const std::string& text)
{
    auto* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out) std::memcpy(out, text.c_str(), text.size() + 1);
    return out;
}

std::string dump(const json& value)
{
    return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

// The canonical error object a dispatch returns for a failed call.
char* failure(const std::string& code, const std::string& message, const std::string& origin)
{
    return heapCopy(dump(json{{"code", code}, {"message", message}, {"origin", origin}}));
}

} // namespace

struct Facade::Impl {
    // One upstream session per local consumer, on a route of its own.
    struct Upstream {
        Impl* impl = nullptr;
        std::string consumer;
        lp_client* client = nullptr;
        std::mutex mutex;
        std::string ticket;
        std::string route;
        Clock::time_point renewAt{};
    };

    explicit Impl(FacadeOptions opts) : options(std::move(opts)) {}

    json callPeering(const std::string& method, const json& args)
    {
        char* out = nullptr;
        char* err = nullptr;
        const std::string text = dump(args);
        const int status = lp_invoke(peering, method.c_str(), text.c_str(), kPeeringTimeoutMs, &out, &err);
        json result = json{{"error", "UNREACHABLE: " + options.peering}};
        if (status == LP_OK && out) {
            auto parsed = json::parse(out, nullptr, false);
            if (parsed.is_object()) result = std::move(parsed);
        }
        lp_string_free(out);
        lp_string_free(err);
        return result;
    }

    Upstream* upstreamFor(const std::string& consumer, std::string& error)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto& slot = upstreams[consumer];
        if (slot) return slot.get();
        auto upstream = std::make_unique<Upstream>();
        upstream->impl = this;
        upstream->consumer = consumer;
        upstream->client = lp_client_create(module.c_str(), options.name.c_str(),
                                            R"({"protocol":"tls_tcp"})", nullptr);
        if (!upstream->client
            || lp_client_set_tls_credential(upstream->client, chainPem.c_str(), keyPem.c_str()) != LP_OK
            || lp_client_set_session_hook(upstream->client, &Impl::dial, &Impl::hello, upstream.get())
                   != LP_OK) {
            if (upstream->client) lp_client_destroy(upstream->client);
            upstreams.erase(consumer);
            error = "no upstream client";
            return nullptr;
        }
        slot = std::move(upstream);
        return slot.get();
    }

    // Before each dial: a route for this consumer, from peering_module.
    static char* dial(const char*, void* userData)
    {
        auto* upstream = static_cast<Upstream*>(userData);
        Impl& impl = *upstream->impl;
        const json route = impl.callPeering(
            "requestRoute", json::array({upstream->consumer, impl.options.callTimeout.count()}));
        if (route.contains("error") || !route.contains("ticket"))
            return heapCopy(dump(json{{"error", route.value("error", std::string("no route"))}}));
        {
            std::lock_guard<std::mutex> lock(upstream->mutex);
            upstream->ticket = route.value("ticket", "");
            upstream->route = route.value("route", "");
            upstream->renewAt = Clock::now() + std::chrono::milliseconds(route.value("lifetime_ms", 0) / 2);
        }
        return heapCopy(dump(json{{"addresses", route.value("addresses", json::array())},
                                  {"port", route.value("port", 0)},
                                  {"server_pin", route.value("server_pin", "")},
                                  {"anchors", route.value("anchors", "")}}));
    }

    static char* hello(const char*, void* userData)
    {
        auto* upstream = static_cast<Upstream*>(userData);
        std::lock_guard<std::mutex> lock(upstream->mutex);
        return heapCopy(dump(json{{"ticket", upstream->ticket}, {"module", upstream->impl->module}}));
    }

    static char* dispatch(const char* method, const char* args, void* userData)
    {
        auto& impl = *static_cast<Impl*>(userData);
        const auto consumer = consumerForCallerJson(lp_current_caller_json());
        if (!consumer) return failure("unauthorized", "this caller cannot be named upstream", impl.options.name);
        std::string error;
        Upstream* upstream = impl.upstreamFor(*consumer, error);
        if (!upstream) return failure("dispatch_failed", "remote/unavailable: " + error, impl.options.name);
        char* out = nullptr;
        char* err = nullptr;
        const int status = lp_invoke(upstream->client, method, args ? args : "[]",
                                     static_cast<int>(impl.options.callTimeout.count()), &out, &err);
        char* reply = nullptr;
        if (status == LP_OK) {
            impl.want("ready", {});
            reply = heapCopy(out ? out : "null");
        } else {
            const json detail = json::parse(err ? err : "{}", nullptr, false);
            const std::string code = detail.is_object() ? detail.value("code", "unavailable") : "unavailable";
            const std::string message = detail.is_object() ? detail.value("message", "") : "";
            if (code == "unavailable" || code == "timeout") impl.want("error", "remote/" + code + ": " + message);
            reply = failure("dispatch_failed", "remote/" + code + ": " + message, impl.options.name);
        }
        lp_string_free(out);
        lp_string_free(err);
        return reply;
    }

    static char* methods(void* userData)
    {
        auto& impl = *static_cast<Impl*>(userData);
        std::lock_guard<std::mutex> lock(impl.mutex);
        return heapCopy(impl.methodsJson);
    }

    static void onEvent(const char* event, const char* data, void* userData)
    {
        auto& impl = *static_cast<Impl*>(userData);
        if (event && *event) lp_provider_emit_event(impl.provider, event, data ? data : "[]");
    }

    // The state peering_module should hear; the worker sends it.
    void want(const std::string& state, const std::string& reason)
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (wantedState == state && wantedReason == reason) return;
            wantedState = state;
            wantedReason = reason;
        }
        wake.notify_all();
    }

    // Fetches the interface over the runtime session and publishes the facade.
    bool publish(std::string& error)
    {
        Upstream* runtime = upstreamFor("runtime", error);
        if (!runtime) return false;
        char* text = lp_get_methods(runtime->client);
        const json interface = json::parse(text ? text : "", nullptr, false);
        lp_string_free(text);
        if (!interface.is_array()) {
            error = "the peer's " + module + " is unreachable";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            methodsJson = dump(interface);
        }
        const int status = lp_provider_register(provider, &Impl::dispatch, &Impl::methods, nullptr, this);
        if (status != LP_OK) {
            error = "the facade could not be published (status " + std::to_string(status) + ")";
            return false;
        }
        if (events) subscription = lp_subscribe(runtime->client, "", &Impl::onEvent, this);
        return true;
    }

    void renewDue()
    {
        std::vector<Upstream*> due;
        {
            std::lock_guard<std::mutex> lock(mutex);
            const auto now = Clock::now();
            for (auto& [consumer, upstream] : upstreams) {
                std::lock_guard<std::mutex> guard(upstream->mutex);
                if (!upstream->route.empty() && upstream->renewAt <= now) due.push_back(upstream.get());
            }
        }
        for (Upstream* upstream : due) {
            std::string route;
            {
                std::lock_guard<std::mutex> guard(upstream->mutex);
                route = upstream->route;
            }
            const json renewed = callPeering("renewRoute", json::array({route}));
            std::lock_guard<std::mutex> guard(upstream->mutex);
            if (renewed.contains("lifetime_ms") && upstream->route == route)
                upstream->renewAt = Clock::now() + std::chrono::milliseconds(renewed.value("lifetime_ms", 0) / 2);
            else if (upstream->route == route)
                upstream->route.clear(); // it lapses; the next call dials a new one
        }
    }

    void run()
    {
        bool published = false;
        auto nextHealth = Clock::now() + kHealthInterval;
        std::unique_lock<std::mutex> lock(mutex);
        while (!stopping) {
            if (!published) {
                lock.unlock();
                std::string error;
                published = publish(error);
                if (published) want("ready", {});
                else want("error", error);
                lock.lock();
            }
            if (wantedState != reportedState || wantedReason != reportedReason) {
                const std::string state = wantedState;
                const std::string reason = wantedReason;
                lock.unlock();
                const json reply = callPeering("reportImportState", json::array({state, reason}));
                lock.lock();
                if (!reply.contains("error")) {
                    reportedState = state;
                    reportedReason = reason;
                }
            }
            lock.unlock();
            if (published) renewDue();
            if (published && Clock::now() >= nextHealth) {
                nextHealth = Clock::now() + kHealthInterval;
                std::string error;
                Upstream* runtime = upstreamFor("runtime", error);
                char* text = runtime ? lp_get_methods(runtime->client) : nullptr;
                if (text) want("ready", {});
                else want("error", "the peer's " + module + " is unreachable");
                lp_string_free(text);
            }
            lock.lock();
            if (stopping) break;
            wake.wait_for(lock, published ? std::chrono::milliseconds(1000) : options.retry);
        }
    }

    FacadeOptions options;
    lp_client* peering = nullptr;
    lp_provider* provider = nullptr;
    std::string module;
    bool events = false;
    std::string chainPem;
    std::string keyPem;

    std::mutex mutex;
    std::condition_variable wake;
    bool stopping = false;
    std::string methodsJson = "[]";
    std::string wantedState = "connecting";
    std::string wantedReason;
    std::string reportedState;
    std::string reportedReason;
    std::map<std::string, std::unique_ptr<Upstream>> upstreams;
    lp_subscription* subscription = nullptr;
    std::thread worker;
};

Facade::Facade(FacadeOptions options) : impl_(std::make_shared<Impl>(std::move(options))) {}

Facade::~Facade() { stop(); }

bool Facade::start(std::string& error)
{
    Impl& impl = *impl_;
    // Calls to peering_module go as this facade, on the runtime's credential.
    if (lp_token_save("core", impl.options.credential.c_str()) != LP_OK
        || lp_token_save("capability_module", impl.options.credential.c_str()) != LP_OK) {
        error = "the facade could not keep its credential";
        return false;
    }
    impl.peering = lp_client_create(impl.options.peering.c_str(), impl.options.name.c_str(), nullptr, nullptr);
    if (!impl.peering) {
        error = "no client for " + impl.options.peering;
        return false;
    }
    const json descriptor = impl.callPeering("importDescriptor", json::array());
    impl.module = descriptor.value("module", "");
    impl.events = descriptor.value("events", false);
    if (impl.module.empty()) {
        error = impl.options.peering + " has no import named " + impl.options.name + " ("
            + descriptor.value("error", std::string("no answer")) + ")";
        return false;
    }
    const PKey key = generateP256();
    const json issued = impl.callPeering("issueCertificate", json::array({"client", makeCsrPem(key.get())}));
    if (!issued.contains("chain_pem")) {
        error = "no client certificate (" + issued.value("error", std::string("no answer")) + ")";
        return false;
    }
    impl.chainPem = issued.value("chain_pem", "");
    impl.keyPem = privateKeyPem(key.get());

    impl.provider = lp_provider_create(impl.options.name.c_str(), impl.options.transportSet.c_str());
    if (!impl.provider) {
        error = "the facade's transport set is unusable";
        return false;
    }
    if (lp_provider_set_max_concurrent_calls(impl.provider, impl.options.maxCalls) != LP_OK
        || lp_provider_save_token(impl.provider, "core", impl.options.credential.c_str()) != LP_OK
        || lp_provider_prepare(impl.provider, &Impl::dispatch, &Impl::methods, nullptr, &impl) != LP_OK) {
        error = "the facade could not be prepared";
        lp_provider_destroy(impl.provider);
        impl.provider = nullptr;
        return false;
    }
    impl.worker = std::thread([&impl] { impl.run(); });
    return true;
}

void Facade::stop()
{
    Impl& impl = *impl_;
    {
        std::lock_guard<std::mutex> lock(impl.mutex);
        impl.stopping = true;
    }
    impl.wake.notify_all();
    if (impl.worker.joinable()) impl.worker.join();
    if (impl.subscription) lp_unsubscribe(impl.subscription);
    impl.subscription = nullptr;
    // No call reaches an upstream client once the provider is gone.
    if (impl.provider) lp_provider_destroy(impl.provider);
    impl.provider = nullptr;
    std::map<std::string, std::unique_ptr<Impl::Upstream>> upstreams;
    {
        std::lock_guard<std::mutex> lock(impl.mutex);
        upstreams.swap(impl.upstreams);
    }
    for (auto& [consumer, upstream] : upstreams)
        if (upstream->client) lp_client_destroy(upstream->client);
    if (impl.peering) lp_client_destroy(impl.peering);
    impl.peering = nullptr;
}

lp_provider* Facade::provider() const { return impl_->provider; }

} // namespace logos::peering
