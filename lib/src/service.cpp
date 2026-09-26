#include "logos/peering/service.h"

#include "logos/peering/audit.h"
#include "logos/peering/callers.h"
#include "logos/peering/config.h"
#include "logos/peering/enrollment.h"
#include "logos/peering/fs.h"
#include "logos/peering/identity.h"
#include "logos/peering/invite_store.h"
#include "logos/peering/invites.h"
#include "logos/peering/names.h"
#include "logos/peering/pairing_session.h"
#include "logos/peering/routes.h"
#include "logos/peering/tickets.h"

#include <logos_protocol.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

namespace logos::peering {

using json = nlohmann::json;
using SteadyClock = std::chrono::steady_clock;

namespace {

constexpr auto kControlLeafValidity = std::chrono::hours(24 * 90);
constexpr auto kControlLeafRenewBelow = std::chrono::hours(24 * 30);
constexpr auto kHostLeafValidity = std::chrono::hours(24 * 30);
constexpr auto kRouteLifetime = std::chrono::seconds(3600);
constexpr auto kTicketTtl = std::chrono::seconds(30);
constexpr auto kPairingLifetime = std::chrono::minutes(5);
constexpr auto kFinishedKept = std::chrono::seconds(60);
constexpr std::int64_t kControlSessionMs = 3600 * 1000;
constexpr int kLinkTimeoutMs = 15000;
constexpr std::int64_t kMaxFrame = 16 * 1024 * 1024;
constexpr std::size_t kMaxIncomingPairings = 16;

json fault(const std::string& code) { return json{{"error", code}}; }

bool isFault(const json& value) { return value.is_object() && value.contains("error"); }

std::string dump(const json& value)
{
    return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

char* heapCopy(const std::string& text)
{
    auto* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out) std::memcpy(out, text.c_str(), text.size() + 1);
    return out;
}

std::optional<std::string> textArg(const json& args, std::size_t index)
{
    if (!args.is_array() || args.size() <= index || !args[index].is_string()) return std::nullopt;
    return args[index].get<std::string>();
}

std::optional<std::int64_t> intArg(const json& args, std::size_t index)
{
    if (!args.is_array() || args.size() <= index || !args[index].is_number_integer())
        return std::nullopt;
    return args[index].get<std::int64_t>();
}

const json* objectArg(const json& args, std::size_t index)
{
    if (!args.is_array() || args.size() <= index || !args[index].is_object()) return nullptr;
    return &args[index];
}

bool isPin(const std::string& pin)
{
    if (pin.rfind("sha256:", 0) != 0) return false;
    const auto raw = fromBase64url(pin.substr(7));
    return raw && raw->size() == 32;
}

// A presented chain: exactly a leaf and the root that issued it.
struct Presented {
    Cert leaf;
    Cert root;
    Bytes leafSpki;
    Bytes rootSpki;
};

std::optional<Presented> presentedChain(const json& chain, Role role)
{
    if (!chain.is_array() || chain.size() != 2 || !chain[0].is_string() || !chain[1].is_string())
        return std::nullopt;
    const auto leafDer = fromBase64url(chain[0].get<std::string>());
    const auto rootDer = fromBase64url(chain[1].get<std::string>());
    if (!leafDer || !rootDer) return std::nullopt;
    Presented out{certFromDer(*leafDer), certFromDer(*rootDer), {}, {}};
    if (!out.leaf || !out.root || !verifyLeaf(out.leaf.get(), out.root.get(), role).empty())
        return std::nullopt;
    out.leafSpki = spkiDer(out.leaf.get());
    out.rootSpki = spkiDer(out.root.get());
    return out;
}

std::string addressOf(const std::string& remote)
{
    const auto colon = remote.rfind(':');
    return colon == std::string::npos ? remote : remote.substr(0, colon);
}

bool isLoopback(const std::string& address)
{
    return address.rfind("127.", 0) == 0 || address == "::1" || address.rfind("::ffff:127.", 0) == 0;
}

constexpr const char* kLocalIssuer = "@local";

// The first address of an interface that is up and not loopback.
std::string guessAddress()
{
#ifndef _WIN32
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return {};
    std::string found;
    for (ifaddrs* it = list; it && found.empty(); it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
        if (!(it->ifa_flags & IFF_UP) || (it->ifa_flags & IFF_LOOPBACK)) continue;
        char text[INET_ADDRSTRLEN] = {};
        const auto* in = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
        if (inet_ntop(AF_INET, &in->sin_addr, text, sizeof text)) found = text;
    }
    freeifaddrs(list);
    return found;
#else
    return {};
#endif
}

std::string aliasFrom(const std::string& displayName)
{
    std::string alias;
    for (const unsigned char c : displayName) {
        if (alias.size() >= 48) break;
        if (std::isalnum(c)) alias.push_back(static_cast<char>(std::tolower(c)));
        else if (!alias.empty() && alias.back() != '-') alias.push_back('-');
    }
    while (!alias.empty() && alias.back() == '-') alias.pop_back();
    return isValidAlias(alias) ? alias : "peer";
}

int64_t msUntil(SteadyClock::time_point when)
{
    return std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(
                                    when - SteadyClock::now()).count());
}

// Calls `method` over a client; the result, or {"error": ...}.
json linkInvoke(lp_client* client, const std::string& method, const json& args,
                int timeoutMs = kLinkTimeoutMs)
{
    if (!client) return fault("UNREACHABLE");
    char* out = nullptr;
    char* err = nullptr;
    const std::string text = dump(args);
    const int status = lp_invoke(client, method.c_str(), text.c_str(), timeoutMs, &out, &err);
    json result = fault("UNREACHABLE");
    if (status == LP_OK && out) {
        auto parsed = json::parse(out, nullptr, false);
        result = parsed.is_discarded() ? fault("MALFORMED_REPLY") : std::move(parsed);
    } else if (err) {
        const auto parsed = json::parse(err, nullptr, false);
        const std::string message = parsed.is_object() ? parsed.value("message", "") : "";
        result = fault(message.empty() ? "UNREACHABLE" : "UNREACHABLE: " + message);
    }
    lp_string_free(out);
    lp_string_free(err);
    return result;
}

} // namespace

struct PeeringService::Impl : std::enable_shared_from_this<PeeringService::Impl> {
    struct Self {
        std::string runtimeId;
        std::string rootPem;
        Bytes rootSpki;
        std::string displayId;
    };

    // This runtime dialled another to pair.
    struct Outgoing {
        Impl* impl = nullptr;
        std::string id;
        std::unique_ptr<PairingInitiator> initiator;
        lp_client* client = nullptr;
        std::string host;
        std::uint16_t port = 0;
        std::string expectedRootDigest; // from an invite
        bool invite = false;
        bool transportSeen = false;
        std::string peerRootPem;
        std::string peerLeafPin;
        std::string peerDisplayId;
        bool confirmed = false;
        bool polling = false;
        std::string state = "code"; // code | confirming | paired | failed
        std::string error;
        std::string peerRuntimeId;
        SteadyClock::time_point expires;
    };

    // Another runtime dialled this one to pair.
    struct Incoming {
        std::unique_ptr<PairingResponder> responder;
        std::string rootPem;
        std::string leafPin;
        std::string displayId;
        std::string address;
        std::uint16_t controlPort = 0;
        bool finished = false;
        json result;
        SteadyClock::time_point expires;
    };

    struct ExportState {
        bool loaded = false;
        std::int64_t epoch = 0;
        std::uint16_t port = 0;
        std::string providerPin;
    };

    struct FacadeState {
        bool loaded = false;
        std::int64_t epoch = 0;
        std::string clientPin;
        std::string state = "configured";
        std::string reason;
    };

    // An outbound control link to an enrolled peer.
    struct Link {
        Impl* impl = nullptr;
        std::string peer;
        lp_client* client = nullptr;
    };

    explicit Impl(Options opts)
        : options(std::move(opts))
        , enrollments(options.stateDir / "enrollments.json")
        , invites(options.stateDir / "invites.json")
        , tickets(kTicketTtl)
        , audit(options.stateDir / "audit.log")
    {
    }

    // ── lifecycle ───────────────────────────────────────────────────────────

    bool start(std::string& error)
    {
        if (!ensurePrivateDir(options.stateDir, &error)) return false;
        if (!enrollments.load(&error) || !invites.load(&error)) return false;
        loadLocal();
        worker = std::thread([this] { run(); });
        return true;
    }

    void shutdown()
    {
        {
            std::lock_guard<std::mutex> lock(m);
            stopping = true;
        }
        wake.notify_all();
        if (worker.joinable()) worker.join();
        lp_provider* provider = nullptr;
        std::map<std::string, std::unique_ptr<Link>> oldLinks;
        std::map<std::string, std::unique_ptr<Outgoing>> oldOutgoing;
        {
            std::lock_guard<std::mutex> lock(m);
            provider = control;
            control = nullptr;
            oldLinks.swap(links);
            oldOutgoing.swap(outgoing);
        }
        if (provider) lp_provider_destroy(provider);
        for (auto& [peer, link] : oldLinks)
            if (link->client) lp_client_destroy(link->client);
        for (auto& [id, pairing] : oldOutgoing)
            if (pairing->client) lp_client_destroy(pairing->client);
    }

    void emit(const std::string& event, json args = json::array())
    {
        if (options.emit) options.emit(event, args);
    }

    // ── persistent local state ──────────────────────────────────────────────

    void loadLocal()
    {
        const auto text = readFile(options.stateDir / "local.json");
        if (!text) return;
        const auto doc = json::parse(*text, nullptr, false);
        if (!doc.is_object()) return;
        if (doc.contains("exports") && doc["exports"].is_object())
            for (const auto& item : doc["exports"].items())
                if (auto rule = parseExportRule(item.value())) localExports[item.key()] = *rule;
        if (doc.contains("imports") && doc["imports"].is_object())
            for (const auto& item : doc["imports"].items())
                if (auto rule = parseImportRule(item.key(), item.value())) localImports[item.key()] = *rule;
        if (doc.contains("policy") && doc["policy"].is_object()) policy = doc["policy"];
    }

    void saveLocalLocked()
    {
        json exportsDoc = json::object();
        for (const auto& [name, rule] : localExports) exportsDoc[name] = toJson(rule);
        json importsDoc = json::object();
        for (const auto& [name, rule] : localImports) importsDoc[name] = toJson(rule);
        writeFileAtomically(options.stateDir / "local.json",
                            dump(json{{"version", 1}, {"exports", exportsDoc}, {"imports", importsDoc},
                                      {"policy", policy}}) + "\n");
    }

    // ── identity and the control credential ─────────────────────────────────

    std::optional<Self> self(std::string* error = nullptr)
    {
        {
            std::lock_guard<std::mutex> lock(m);
            if (identity) return identity;
        }
        if (!options.identity) {
            if (error) *error = "no identity source";
            return std::nullopt;
        }
        const auto info = options.identity->info(error);
        if (!info) return std::nullopt;
        const Cert root = certFromPem(info->rootCertPem);
        if (!root || !isUuid(info->runtimeId)) {
            if (error) *error = "peering_identity answered a malformed identity";
            return std::nullopt;
        }
        Self s{info->runtimeId, info->rootCertPem, spkiDer(root.get()), info->displayId};
        std::lock_guard<std::mutex> lock(m);
        identity = s;
        return s;
    }

    Bytes announceKeyLocked()
    {
        if (!announceKey.empty()) return announceKey;
        const auto path = options.stateDir / "announce.key";
        if (const auto text = readFile(path)) {
            if (auto raw = fromBase64url(*text); raw && raw->size() == 32) announceKey = *raw;
        }
        if (announceKey.empty()) {
            announceKey = randomBytes(32);
            writeFileAtomically(path, base64url(announceKey));
        }
        return announceKey;
    }

    PairingParty partyLocked(const Self& s)
    {
        return PairingParty{s.runtimeId, s.rootSpki,
                            config.name.empty() ? std::string("Logos runtime") : config.name,
                            announceKeyLocked()};
    }

    // The persistent control key and a leaf for it, re-issued when it runs low.
    bool ensureControlCredential(std::string& error)
    {
        const auto s = self(&error);
        if (!s) return false;
        Bytes spki;
        {
            std::lock_guard<std::mutex> lock(m);
            if (!controlKey) {
                const auto path = options.stateDir / "control.key.pem";
                if (const auto pem = readFile(path)) controlKey = privateKeyFromPem(*pem);
                if (!controlKey || !isP256(controlKey.get())) {
                    controlKey = generateP256();
                    if (!writeFileAtomically(path, privateKeyPem(controlKey.get()), &error)) {
                        controlKey.reset();
                        return false;
                    }
                }
            }
            if (!controlChainPem.empty() && SteadyClock::now() + kControlLeafRenewBelow < controlLeafExpires)
                return true;
            spki = spkiDer(controlKey.get());
        }
        const auto leaf = options.identity->issue(Role::Control, spki,
            std::chrono::duration_cast<std::chrono::seconds>(kControlLeafValidity), &error);
        if (!leaf) return false;
        std::lock_guard<std::mutex> lock(m);
        controlChainPem = *leaf + s->rootPem;
        controlLeafExpires = SteadyClock::now() + kControlLeafValidity;
        controlLeafPin = spkiPin(spki);
        return true;
    }

    std::string activeAnchorsLocked() const
    {
        std::string pem;
        for (const auto& e : enrollments.all())
            if (e.status == "active") pem += e.trustAnchorPem;
        return pem;
    }

    bool windowOpenLocked() const { return SteadyClock::now() < windowUntil; }

    // A live invite lets unknown roots pair; the local one only over loopback.
    bool invitesAdmit(bool loopback)
    {
        for (const auto& invite : invites.live())
            if (loopback || invite.issuedBy != kLocalIssuer) return true;
        return false;
    }

    // Keeps a live local invite in its file while configured, and replaces it
    // once used or expired.
    void refreshLocalInvite()
    {
        PeeringConfig cfg;
        std::string digest;
        {
            std::lock_guard<std::mutex> lock(m);
            cfg = config;
            digest = localInviteDigest;
        }
        const std::filesystem::path path = cfg.localInvitePath.empty()
            ? options.stateDir / "local-invite" : std::filesystem::u8path(cfg.localInvitePath);
        std::error_code ignored;
        if (!cfg.control || !cfg.localInvite) {
            if (digest.empty()) return;
            invites.revoke(digest);
            std::filesystem::remove(path, ignored);
            std::lock_guard<std::mutex> lock(m);
            localInviteDigest.clear();
            return;
        }
        bool live = false;
        for (const auto& invite : invites.live())
            if (!digest.empty() && invite.secretDigest == digest) live = true;
        if (live && std::filesystem::exists(path, ignored)) return;
        const std::uint16_t port = boundControlPort();
        const auto s = self();
        if (!port || !s) return;
        if (!digest.empty()) invites.revoke(digest);
        const std::string role =
            cfg.localInviteRole == "operator" && cfg.operatorRoutes ? "operator" : "peer";
        const std::string secret = invites.issue(role, std::chrono::seconds(0), kLocalIssuer);
        Invite invite;
        invite.runtimeId = s->runtimeId;
        invite.rootDigest = base64url(sha256(s->rootSpki));
        invite.secret = secret;
        invite.host = "127.0.0.1";
        invite.port = port;
        std::filesystem::create_directories(path.parent_path(), ignored);
        if (!writeFileAtomically(path, formatInvite(invite) + "\n")) {
            invites.revoke(inviteSecretDigest(secret));
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m);
            localInviteDigest = inviteSecretDigest(secret);
        }
        refreshControl();
    }

    // ── the control endpoint ────────────────────────────────────────────────

    void refreshControl()
    {
        lp_provider* provider = nullptr;
        std::string anchors;
        bool admit = false;
        {
            std::lock_guard<std::mutex> lock(m);
            provider = control;
            anchors = activeAnchorsLocked();
            admit = windowOpenLocked() || invites.anyLive();
        }
        if (!provider) return;
        lp_provider_set_trust_anchors(provider, anchors.c_str());
        lp_provider_set_unanchored_admission(provider, admit ? 1 : 0);
    }

    json ensureControl()
    {
        PeeringConfig cfg;
        lp_provider* stale = nullptr;
        {
            std::lock_guard<std::mutex> lock(m);
            cfg = config;
            const bool same = control && controlHost == cfg.controlHost && controlPortWanted == cfg.controlPort;
            if (cfg.control && same) {
                // Credentials and anchors may have moved; the listener stays.
            } else {
                stale = control;
                control = nullptr;
            }
        }
        if (stale) lp_provider_destroy(stale);
        if (!cfg.control) return json{{"ok", true}};
        std::string error;
        if (!ensureControlCredential(error)) return fault("IDENTITY_UNAVAILABLE: " + error);
        std::string chain;
        std::string key;
        bool exists = false;
        {
            std::lock_guard<std::mutex> lock(m);
            chain = controlChainPem;
            key = privateKeyPem(controlKey.get());
            exists = control != nullptr;
        }
        if (exists) {
            std::lock_guard<std::mutex> lock(m);
            lp_provider_set_tls_credential(control, chain.c_str(), key.c_str());
        } else {
            const std::string transport = dump(json::array(
                {{{"protocol", "tls_tcp"}, {"host", cfg.controlHost}, {"port", cfg.controlPort}}}));
            lp_provider* provider = lp_provider_create("peering_control", transport.c_str());
            if (!provider) return fault("CONTROL_UNAVAILABLE");
            if (lp_provider_set_tls_credential(provider, chain.c_str(), key.c_str()) != LP_OK
                || lp_provider_set_session_authenticator(provider, &Impl::authenticateCb, this) != LP_OK
                || lp_provider_set_max_concurrent_calls(provider, 8) != LP_OK
                || lp_provider_register(provider, &Impl::dispatchCb, &Impl::methodsCb, nullptr, this)
                       != LP_OK) {
                lp_provider_destroy(provider);
                return fault("CONTROL_UNAVAILABLE: cannot listen on " + cfg.controlHost + ":"
                             + std::to_string(cfg.controlPort));
            }
            std::lock_guard<std::mutex> lock(m);
            control = provider;
            controlHost = cfg.controlHost;
            controlPortWanted = cfg.controlPort;
        }
        refreshControl();
        return json{{"ok", true}, {"port", boundControlPort()}};
    }

    std::uint16_t boundControlPort()
    {
        lp_provider* provider = nullptr;
        {
            std::lock_guard<std::mutex> lock(m);
            provider = control;
        }
        if (!provider) return 0;
        char* text = lp_provider_endpoints_json(provider);
        const auto endpoints = json::parse(text ? text : "[]", nullptr, false);
        lp_string_free(text);
        if (endpoints.is_array())
            for (const auto& e : endpoints)
                if (e.is_object() && e.value("protocol", "") == "tls_tcp")
                    return static_cast<std::uint16_t>(e.value("port", 0));
        return 0;
    }

    static char* authenticateCb(const char* request, void* userData)
    {
        auto* impl = static_cast<Impl*>(userData);
        json reply;
        try {
            reply = impl->authenticateControl(request ? request : "");
        } catch (...) {
            reply = fault("NOT_AUTHORISED");
        }
        return heapCopy(dump(reply));
    }

    static char* dispatchCb(const char* method, const char* args, void* userData)
    {
        auto* impl = static_cast<Impl*>(userData);
        const std::string caller = lp_current_caller_json();
        json parsed = json::parse(args ? args : "[]", nullptr, false);
        if (!parsed.is_array()) parsed = json::array();
        json reply;
        try {
            reply = impl->controlCall(caller, method ? method : "", parsed);
        } catch (...) {
            reply = fault("FAILED");
        }
        return heapCopy(dump(reply));
    }

    static char* methodsCb(void*) { return heapCopy("[]"); }

    json authenticateControl(const std::string& text)
    {
        const auto request = parseStrictObject(text);
        if (!request || !request->contains("hello") || !(*request)["hello"].is_object())
            return fault("NOT_AUTHORISED");
        const json& hello = (*request)["hello"];
        const std::string purpose = hello.value("purpose", "");
        const auto chain = presentedChain(request->value("peer_chain", json()), Role::Control);
        const auto exporter = fromBase64url(request->value("exporter", ""));
        const bool anchored = request->value("anchored", false);
        if (!chain || !exporter || exporter->size() != 32) return fault("NOT_AUTHORISED");
        const std::string rootPin = spkiPin(chain->rootSpki);
        const std::string leafPin = spkiPin(chain->leafSpki);
        const auto s = self();
        if (!s) return fault("NOT_AUTHORISED");

        std::lock_guard<std::mutex> lock(m);
        if (anchored && purpose == "control") {
            const auto e = enrollments.findByAnchorPin(rootPin);
            if (!e || e->status != "active"
                || std::find(e->subjectPublicKeys.begin(), e->subjectPublicKeys.end(), leafPin)
                       == e->subjectPublicKeys.end())
                return fault("NOT_AUTHORISED");
            return json{{"caller", remotePrincipal(e->runtimeInstanceId, "peering_module")},
                        {"lifetime_ms", kControlSessionMs},
                        {"session", {{"peer", e->runtimeInstanceId},
                                     {"generation", routes.generation(e->runtimeInstanceId)}}}};
        }
        const std::string address = addressOf(request->value("remote", ""));
        const bool loopback = isLoopback(address);
        if (anchored || purpose != "pairing" || !(windowOpenLocked() || invitesAdmit(loopback))
            || enrollments.findByAnchorPin(rootPin) || constantTimeEqual(chain->rootSpki, s->rootSpki))
            return fault("NOT_AUTHORISED");
        purgeIncomingLocked();
        if (incoming.size() >= kMaxIncomingPairings) return fault("BUSY");
        const std::string sid = base64url(randomBytes(12));
        Incoming in;
        in.responder = std::make_unique<PairingResponder>(partyLocked(*s),
            [this, loopback](const std::string& secret) -> std::optional<std::string> {
                // The local invite is for this machine only.
                const auto invite = invites.redeem(secret, [loopback](const IssuedInvite& i) {
                    return loopback || i.issuedBy != kLocalIssuer;
                });
                if (!invite) return std::nullopt;
                audit.record("invite_redeemed", {{"role", invite->role}, {"issued_by", invite->issuedBy}});
                wake.notify_all();
                return invite->role;
            },
            windowOpenLocked());
        in.responder->setTransport(chain->rootSpki, *exporter);
        in.rootPem = certPem(chain->root.get());
        in.leafPin = leafPin;
        in.displayId = displayIdFor(chain->rootSpki);
        in.address = address;
        in.expires = SteadyClock::now() + kPairingLifetime;
        incoming[sid] = std::move(in);
        return json{{"caller", remotePrincipal("pairing:" + sid, "pairing")},
                    {"lifetime_ms", std::chrono::duration_cast<std::chrono::milliseconds>(kPairingLifetime).count()},
                    {"session", {{"pairing", sid}}}};
    }

    void purgeIncomingLocked()
    {
        const auto now = SteadyClock::now();
        for (auto it = incoming.begin(); it != incoming.end();)
            it = it->second.expires <= now ? incoming.erase(it) : std::next(it);
    }

    json pendingEntryLocked(const std::string& id, const Incoming& in) const
    {
        return json{{"id", id},
                    {"direction", "incoming"},
                    {"code", in.responder->code()},
                    {"peer_display_id", in.displayId},
                    {"peer_name", in.responder->initiatorDisplayName()},
                    {"peer_runtime_id", in.responder->initiatorRuntimeId()},
                    {"role", in.responder->grantedRole()},
                    {"needs_approval", in.responder->needsApproval()},
                    {"expires_ms", msUntil(in.expires)}};
    }

    json controlCall(const std::string& callerText, const std::string& method, const json& args)
    {
        const auto caller = parseStrictObject(callerText);
        if (!caller || caller->value("kind", "") != "remote") return fault("NOT_AUTHORISED");
        const std::string peer = caller->value("peer", "");
        if (peer.rfind("pairing:", 0) == 0) return pairingCall(peer.substr(8), method, args);
        {
            std::lock_guard<std::mutex> lock(m);
            const auto e = enrollments.find(peer);
            if (!e || e->status != "active") return fault("NOT_AUTHORISED");
        }
        if (method == "listExports") return listExportsFor(peer);
        if (method == "establishRoute") return establishRoute(peer, objectArg(args, 0));
        if (method == "renewRoute") {
            const auto id = textArg(args, 0);
            if (!id) return fault("INVALID_ARGUMENT");
            const auto lifetime = routes.renew(*id, peer, kRouteLifetime);
            if (!lifetime) return fault("NOT_AUTHORISED");
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(*lifetime).count();
            emit("routeRenewed", json::array({*id, ms}));
            return json{{"lifetime_ms", ms}};
        }
        if (method == "peerUpdate") return fault("NOT_SUPPORTED");
        return fault("NO_SUCH_METHOD");
    }

    json pairingCall(const std::string& sid, const std::string& method, const json& args)
    {
        const json* body = objectArg(args, 0);
        if (!body) return fault("INVALID_ARGUMENT");
        json requested;
        json enrolledEvent;
        std::string error;
        {
            std::lock_guard<std::mutex> lock(m);
            const auto it = incoming.find(sid);
            if (it == incoming.end()) return fault("NOT_AUTHORISED");
            Incoming& in = it->second;
            if (in.finished) return in.result;
            if (method == "pairHello") {
                const auto port = body->find("control_port");
                if (port != body->end() && port->is_number_integer() && port->get<std::int64_t>() > 0
                    && port->get<std::int64_t>() <= 65535)
                    in.controlPort = static_cast<std::uint16_t>(port->get<std::int64_t>());
                json clean = *body;
                clean.erase("control_port");
                auto reply = in.responder->onHello(clean, &error);
                if (!reply) {
                    incoming.erase(it);
                    return fault(error);
                }
                return *reply;
            }
            if (method == "pairReveal") {
                if (!in.responder->onReveal(*body, &error)) {
                    incoming.erase(it);
                    return fault(error);
                }
                if (in.responder->needsApproval()) requested = pendingEntryLocked(sid, in);
            } else if (method == "pairConfirm") {
                if (in.responder->rejected()) {
                    in.finished = true;
                    in.result = json{{"status", "rejected"}};
                    in.expires = SteadyClock::now() + kFinishedKept;
                    return in.result;
                }
                if (!in.responder->confirmed() && !in.responder->onConfirm(*body, &error))
                    return fault(error);
                if (!in.responder->ready()) return json{{"status", "waiting"}};
                const PairingOutcome outcome = in.responder->outcome();
                Enrollment e;
                e.runtimeInstanceId = outcome.peerRuntimeId;
                e.trustAnchorPem = in.rootPem;
                e.subjectPublicKeys = {in.leafPin};
                e.alias = uniqueAliasLocked(outcome.peerDisplayName);
                e.role = outcome.role;
                e.grantedRole = "peer";
                e.displayName = outcome.peerDisplayName;
                if (!in.address.empty()) e.addresses = {in.address};
                e.controlPort = in.controlPort;
                in.finished = true;
                in.expires = SteadyClock::now() + kFinishedKept;
                if (!enrollments.add(e, &error) || !enrollments.save(&error)) {
                    enrollments.load();
                    in.result = json{{"status", "rejected"}, {"reason", error}};
                    return in.result;
                }
                audit.record("paired", {{"peer", e.runtimeInstanceId}, {"role", e.role},
                                        {"direction", "incoming"}});
                in.result = in.responder->result();
                enrolledEvent = in.result;
            } else {
                return fault("NOT_AUTHORISED");
            }
        }
        if (!requested.is_null()) emit("pairingRequested", json::array({requested}));
        if (!enrolledEvent.is_null()) {
            refreshControl();
            emit("peersChanged");
            emit("anchorsChanged");
            return enrolledEvent;
        }
        return json{{"ok", true}};
    }

    std::string uniqueAliasLocked(const std::string& displayName) const
    {
        const std::string base = aliasFrom(displayName);
        std::string alias = base;
        for (int n = 2; enrollments.findByAlias(alias); ++n) alias = base + "-" + std::to_string(n);
        return alias;
    }

    // ── exports, imports and policy ─────────────────────────────────────────

    std::map<std::string, ExportRule> exportsLocked() const
    {
        std::map<std::string, ExportRule> all = localExports;
        for (const auto& [name, rule] : config.exportModules) all[name] = rule;
        return all;
    }

    std::map<std::string, ImportRule> importsLocked() const
    {
        std::map<std::string, ImportRule> all = localImports;
        for (const auto& [name, rule] : config.imports) all[name] = rule;
        return all;
    }

    bool policyAllowsLocked(const std::string& peer, const std::string& consumer,
                            const std::string& target) const
    {
        for (const std::string& key : {peer + "/" + consumer, peer + "/*"}) {
            const auto it = policy.find(key);
            if (it == policy.end() || !it->is_array()) continue;
            for (const auto& t : *it)
                if (t.is_string() && t.get<std::string>() == target) return true;
        }
        return false;
    }

    bool policyNamesPeerLocked(const std::string& peer, const std::string& target) const
    {
        for (const auto& item : policy.items()) {
            if (item.key().rfind(peer + "/", 0) != 0 || !item.value().is_array()) continue;
            for (const auto& t : item.value())
                if (t.is_string() && t.get<std::string>() == target) return true;
        }
        return false;
    }

    json listExportsFor(const std::string& peer)
    {
        std::lock_guard<std::mutex> lock(m);
        json out = json::object();
        if (!config.exports) return out;
        for (const auto& [name, rule] : exportsLocked()) {
            if (!policyNamesPeerLocked(peer, name)) continue;
            const auto state = exportStates.find(name);
            out[name] = {{"events", rule.events},
                         {"loaded", state != exportStates.end() && state->second.loaded}};
        }
        return out;
    }

    json establishRoute(const std::string& peer, const json* request)
    {
        if (!request) return fault("INVALID_ARGUMENT");
        const std::string consumer = request->value("consumer", "");
        const std::string target = request->value("target", "");
        const std::string clientPin = request->value("client_pin", "");
        const auto refuse = [&](const std::string& why) {
            audit.record("route_denied", {{"peer", peer}, {"consumer", consumer}, {"target", target},
                                          {"reason", why}});
            return fault("NOT_AUTHORISED");
        };
        if (!isValidConsumer(consumer) || !isValidModuleName(target) || !isPin(clientPin))
            return refuse("malformed request");
        std::uint16_t port = 0;
        std::string serverPin;
        std::int64_t epoch = 0;
        std::string rootPin;
        const bool operatorRoute = target == "core_service";
        {
            std::lock_guard<std::mutex> lock(m);
            const auto e = enrollments.find(peer);
            if (!e || e->status != "active") return refuse("not enrolled");
            rootPin = e->anchorPin();
            if (operatorRoute) {
                if (e->role != "operator" || !config.operatorRoutes || !corePort || corePin.empty())
                    return refuse("no operator route");
                port = corePort;
                serverPin = corePin;
            } else {
                const auto all = exportsLocked();
                const auto state = exportStates.find(target);
                if (!config.exports || !all.count(target) || state == exportStates.end()
                    || !state->second.loaded || !state->second.port || state->second.providerPin.empty())
                    return refuse("not exported or not loaded");
                port = state->second.port;
                serverPin = state->second.providerPin;
                epoch = state->second.epoch;
            }
        }
        bool lookOnly = false;
        if (!operatorRoute) {
            std::optional<bool> allowed;
            if (options.decide) {
                allowed = options.decide(peer, consumer, target);
            } else {
                std::lock_guard<std::mutex> lock(m);
                allowed = policyAllowsLocked(peer, consumer, target);
            }
            if (!allowed) {
                audit.record("route_evaluation_failed", {{"peer", peer}, {"consumer", consumer},
                                                         {"target", target}});
                return fault("NOT_AUTHORISED");
            }
            // A facade's own session may look and listen wherever one of its
            // runtime's consumers may call.
            if (!*allowed && consumer == "runtime") {
                std::lock_guard<std::mutex> lock(m);
                lookOnly = policyNamesPeerLocked(peer, target);
            }
            if (!*allowed && !lookOnly) return refuse("policy");
        }
        Route route;
        route.peer = peer;
        route.consumer = consumer;
        route.target = target;
        route.scope = operatorRoute ? "operator" : lookOnly ? "look" : "calls";
        route.clientPin = clientPin;
        route.endpointEpoch = static_cast<std::uint64_t>(epoch);
        route = routes.add(route, kRouteLifetime);
        const std::string ticket = tickets.mint({{"route", route.id},
                                                 {"peer", peer},
                                                 {"consumer", consumer},
                                                 {"target", target},
                                                 {"client_pin", clientPin},
                                                 {"root_pin", rootPin}});
        routes.attachTicket(route.id, TicketStore::digestOf(ticket));
        audit.record("route", {{"peer", peer}, {"consumer", consumer}, {"target", target},
                               {"route", route.id}});
        return json{{"ticket", ticket},
                    {"route", route.id},
                    {"port", port},
                    {"server_pin", serverPin},
                    {"lifetime_ms", std::chrono::duration_cast<std::chrono::milliseconds>(kRouteLifetime).count()},
                    {"max_frame", kMaxFrame}};
    }

    // ── callers ─────────────────────────────────────────────────────────────

    bool isManagerLocked(const CallerRef& c) const
    {
        if (c.kind == CallerRef::Kind::Module) return !config.shell.empty() && c.name == config.shell;
        if (c.kind == CallerRef::Kind::Operator)
            return !c.name.empty() && c.name != "auto" && c.name.rfind("@peer:", 0) != 0;
        return false;
    }

    bool isReaderLocked(const CallerRef& c) const
    {
        return isManagerLocked(c) || (c.kind == CallerRef::Kind::Operator && !c.name.empty());
    }

    bool isExportHostLocked(const CallerRef& c) const
    {
        if (c.kind != CallerRef::Kind::Module) return false;
        const auto state = exportStates.find(c.name);
        return config.exports && state != exportStates.end() && state->second.loaded
               && exportsLocked().count(c.name);
    }

    bool isCoreServiceLocked(const CallerRef& c) const
    {
        return c.kind == CallerRef::Kind::Module && c.name == "core_service" && config.operatorRoutes;
    }

    bool isFacadeLocked(const CallerRef& c) const
    {
        if (c.kind != CallerRef::Kind::Module) return false;
        const auto state = facades.find(c.name);
        return state != facades.end() && state->second.loaded && importsLocked().count(c.name);
    }

    // ── dispatch ────────────────────────────────────────────────────────────

    json invoke(const CallerRef& caller, const std::string& method, const json& args)
    {
        static const std::set<std::string> engine = {
            "configure", "exportLoaded", "exportExited", "facadeLoaded", "facadeExited"};
        static const std::set<std::string> engineOrReader = {"imports", "importStates", "remotePolicy"};
        static const std::set<std::string> reads = {"status", "peers", "nearby", "pending", "routes",
                                                    "exports"};
        static const std::set<std::string> writes = {
            "openPairingWindow", "pairWith", "confirmPairing", "rejectPairing", "createInvite",
            "redeemInvite", "removePeer", "renamePeer", "setExport", "removeExport", "setImport",
            "removeImport", "setPolicy"};
        static const std::set<std::string> hostMethods = {
            "issueCertificate", "sessionAnchors", "redeemTicket", "noteEndpoints", "sessionState"};
        static const std::set<std::string> facadeMethods = {
            "requestRoute", "renewRoute", "importDescriptor", "reportImportState"};

        const bool isHost = caller.kind == CallerRef::Kind::Host;
        bool allowed = false;
        {
            std::lock_guard<std::mutex> lock(m);
            if (engine.count(method)) allowed = isHost;
            else if (engineOrReader.count(method)) allowed = isHost || isReaderLocked(caller);
            else if (reads.count(method)) allowed = isReaderLocked(caller);
            else if (writes.count(method)) allowed = isManagerLocked(caller);
            else if (method == "issueCertificate")
                allowed = isExportHostLocked(caller) || isCoreServiceLocked(caller) || isFacadeLocked(caller);
            else if (hostMethods.count(method))
                allowed = isExportHostLocked(caller) || isCoreServiceLocked(caller);
            else if (facadeMethods.count(method)) allowed = isFacadeLocked(caller);
            else return fault("NO_SUCH_METHOD");
        }
        if (!allowed) return fault("NOT_AUTHORISED");
        try {
            if (writes.count(method)) {
                std::lock_guard<std::mutex> serial(writeMutex);
                return write(caller, method, args);
            }
            return read(caller, method, args);
        } catch (const std::exception& ex) {
            return fault(std::string("FAILED: ") + ex.what());
        }
    }

    json read(const CallerRef& caller, const std::string& method, const json& args)
    {
        if (method == "configure") return configure(objectArg(args, 0));
        if (method == "exportLoaded" || method == "exportExited" || method == "facadeLoaded"
            || method == "facadeExited")
            return lifecycle(method, textArg(args, 0), intArg(args, 1));
        if (method == "imports") return importsDoc();
        if (method == "importStates") return importStatesDoc();
        if (method == "remotePolicy") {
            std::lock_guard<std::mutex> lock(m);
            return policy;
        }
        if (method == "status") return status();
        if (method == "peers") return peersDoc();
        if (method == "nearby") return json{{"nearby", json::array()}};
        if (method == "pending") return pendingDoc();
        if (method == "routes") return routesDoc();
        if (method == "exports") return exportsDoc();
        if (method == "issueCertificate") return issueCertificate(caller, textArg(args, 0), textArg(args, 1));
        if (method == "sessionAnchors") {
            std::lock_guard<std::mutex> lock(m);
            return json{{"anchors_pem", activeAnchorsLocked()}};
        }
        if (method == "redeemTicket") return redeemTicket(caller, objectArg(args, 0));
        if (method == "noteEndpoints") return noteEndpoints(caller, args.size() ? args[0] : json());
        if (method == "sessionState") return sessionState();
        if (method == "requestRoute") return requestRoute(caller, textArg(args, 0), intArg(args, 1));
        if (method == "renewRoute") return renewImportRoute(caller, textArg(args, 0));
        if (method == "importDescriptor") return importDescriptor(caller);
        if (method == "reportImportState")
            return reportImportState(caller, textArg(args, 0), textArg(args, 1));
        return fault("NO_SUCH_METHOD");
    }

    json write(const CallerRef& caller, const std::string& method, const json& args)
    {
        if (method == "openPairingWindow") return openPairingWindow(intArg(args, 0));
        if (method == "pairWith") return pairWith(textArg(args, 0), intArg(args, 1));
        if (method == "confirmPairing") return decidePairing(textArg(args, 0), true);
        if (method == "rejectPairing") return decidePairing(textArg(args, 0), false);
        if (method == "createInvite") return createInvite(caller, textArg(args, 0), intArg(args, 1));
        if (method == "redeemInvite") return redeemInvite(textArg(args, 0));
        if (method == "removePeer") return removePeer(textArg(args, 0));
        if (method == "renamePeer") return renamePeer(textArg(args, 0), textArg(args, 1));
        if (method == "setExport") return setExport(textArg(args, 0), args.size() > 1 ? args[1] : json());
        if (method == "removeExport") return removeExport(textArg(args, 0));
        if (method == "setImport") return setImport(textArg(args, 0), objectArg(args, 1));
        if (method == "removeImport") return removeImport(textArg(args, 0));
        if (method == "setPolicy") return setPolicy(objectArg(args, 0));
        return fault("NO_SUCH_METHOD");
    }

    // ── engine methods ──────────────────────────────────────────────────────

    json configure(const json* doc)
    {
        std::string error;
        const auto parsed = parsePeeringConfig(doc ? *doc : json(), &error);
        if (!parsed) return fault("INVALID_CONFIG: " + error);
        {
            std::lock_guard<std::mutex> lock(m);
            config = *parsed;
            configured = true;
        }
        const auto s = self(&error);
        if (!s) return fault("IDENTITY_UNAVAILABLE: " + error);
        const json control = ensureControl();
        if (isFault(control)) return control;
        refreshLocalInvite();
        emit("importsChanged");
        emit("exportsChanged");
        emit("remotePolicyChanged");
        return json{{"ok", true}, {"runtime_id", s->runtimeId}, {"control_port", boundControlPort()}};
    }

    json lifecycle(const std::string& method, const std::optional<std::string>& name,
                   const std::optional<std::int64_t>& epoch)
    {
        if (!name || !epoch) return fault("INVALID_ARGUMENT");
        std::vector<std::string> revoked;
        {
            std::lock_guard<std::mutex> lock(m);
            if (method == "exportLoaded") {
                if (!exportsLocked().count(*name)) return fault("NOT_EXPORTED");
                exportStates[*name] = ExportState{true, *epoch, 0, {}};
            } else if (method == "exportExited") {
                auto it = exportStates.find(*name);
                if (it != exportStates.end() && it->second.epoch == *epoch) exportStates.erase(it);
                for (const auto& route : routes.forTarget(*name))
                    if (static_cast<std::int64_t>(route.endpointEpoch) == *epoch) routes.remove(route.id);
            } else if (method == "facadeLoaded") {
                if (!importsLocked().count(*name)) return fault("NOT_IMPORTED");
                FacadeState& f = facades[*name];
                f = FacadeState{};
                f.loaded = true;
                f.epoch = *epoch;
                f.state = "connecting";
            } else {
                auto it = facades.find(*name);
                if (it != facades.end() && it->second.epoch == *epoch) {
                    it->second.loaded = false;
                    it->second.state = "configured";
                    it->second.clientPin.clear();
                }
            }
        }
        return json{{"ok", true}};
    }

    json importsDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        json out = json::object();
        for (const auto& [name, rule] : importsLocked()) {
            json item = toJson(rule);
            const auto e = enrollments.find(rule.from);
            item["peer_alias"] = e ? e->alias : "";
            item["locked"] = config.imports.count(name) > 0;
            out[name] = item;
        }
        return out;
    }

    json importStatesDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        json out = json::object();
        for (const auto& [name, rule] : importsLocked()) {
            const auto e = enrollments.find(rule.from);
            const auto f = facades.find(name);
            if (!e || e->status != "active") out[name] = {{"state", "error"}, {"reason", "the peer is not paired"}};
            else if (f == facades.end()) out[name] = {{"state", "configured"}, {"reason", ""}};
            else out[name] = {{"state", f->second.state}, {"reason", f->second.reason}};
        }
        return out;
    }

    // ── host methods ────────────────────────────────────────────────────────

    json issueCertificate(const CallerRef& caller, const std::optional<std::string>& roleName,
                          const std::optional<std::string>& csrPem)
    {
        if (!roleName || !csrPem) return fault("INVALID_ARGUMENT");
        const auto role = roleFromName(*roleName);
        const auto spki = spkiFromCsrPem(*csrPem);
        if (!role || !spki) return fault("INVALID_ARGUMENT");
        const PKey key = publicKeyFromSpki(*spki);
        if (!key || !isP256(key.get())) return fault("INVALID_ARGUMENT");
        std::string anchors;
        json sessionOptions;
        {
            std::lock_guard<std::mutex> lock(m);
            const bool provider = isExportHostLocked(caller) || isCoreServiceLocked(caller);
            if (*role == Role::Provider && provider) {
                anchors = activeAnchorsLocked();
                if (isExportHostLocked(caller) && config.exportPortMin && config.exportPortMax)
                    sessionOptions = {{"port_min", config.exportPortMin}, {"port_max", config.exportPortMax}};
            } else if (*role == Role::Client && isFacadeLocked(caller)) {
                const auto rule = importsLocked().at(caller.name);
                const auto e = enrollments.find(rule.from);
                if (!e || e->status != "active") return fault("NOT_PAIRED");
                anchors = e->trustAnchorPem;
            } else {
                return fault("NOT_AUTHORISED");
            }
        }
        const auto s = self();
        if (!s) return fault("IDENTITY_UNAVAILABLE");
        std::string error;
        const auto leaf = options.identity->issue(*role, *spki,
            std::chrono::duration_cast<std::chrono::seconds>(kHostLeafValidity), &error);
        if (!leaf) return fault("IDENTITY_UNAVAILABLE: " + error);
        const std::string pin = spkiPin(*spki);
        {
            std::lock_guard<std::mutex> lock(m);
            if (*role == Role::Client) {
                facades[caller.name].clientPin = pin;
            } else if (caller.name == "core_service") {
                corePin = pin;
            } else {
                exportStates[caller.name].providerPin = pin;
            }
        }
        json reply = {{"chain_pem", *leaf + s->rootPem}, {"anchors_pem", anchors}};
        // Where an exported module listens: the configured export ports.
        if (!sessionOptions.is_null()) reply["session_options"] = sessionOptions;
        return reply;
    }

    json redeemTicket(const CallerRef& caller, const json* request)
    {
        if (!request || !request->contains("hello") || !(*request)["hello"].is_object())
            return fault("NOT_AUTHORISED");
        const json& hello = (*request)["hello"];
        const std::string ticket = hello.value("ticket", "");
        const std::string module = hello.value("module", "");
        const std::string exporter = request->value("exporter", "");
        const bool anchored = request->value("anchored", false);
        const auto chain = presentedChain(request->value("peer_chain", json()), Role::Client);
        if (!anchored || module != caller.name || ticket.empty() || exporter.empty() || !chain)
            return fault("NOT_AUTHORISED");
        const std::string leafPin = spkiPin(chain->leafSpki);
        const std::string rootPin = spkiPin(chain->rootSpki);
        const std::string digest = TicketStore::digestOf(ticket);

        std::optional<Route> route;
        if (const auto bound = routes.sessionRoute(exporter)) {
            // The same connection asking again: the same answer.
            route = routes.find(*bound);
            if (!route || route->ticketDigest != digest) return fault("NOT_AUTHORISED");
        } else {
            const auto record = tickets.redeem(ticket, [&](const json& r) {
                return r.value("target", "") == caller.name && r.value("client_pin", "") == leafPin
                       && r.value("root_pin", "") == rootPin;
            });
            if (!record) return fault("NOT_AUTHORISED");
            route = routes.find(record->value("route", ""));
            if (!route || route->generation != routes.generation(route->peer)
                || !routes.bindSession(exporter, route->id))
                return fault("NOT_AUTHORISED");
        }
        {
            std::lock_guard<std::mutex> lock(m);
            const auto e = enrollments.find(route->peer);
            if (!e || e->status != "active" || e->anchorPin() != rootPin) return fault("NOT_AUTHORISED");
        }
        const json principal = route->target == "core_service"
            ? remoteOperatorPrincipal(route->peer) : remotePrincipal(route->peer, route->consumer);
        return json{{"caller", principal},
                    {"lifetime_ms", msUntil(route->expires)},
                    {"session", {{"peer", route->peer},
                                 {"route", route->id},
                                 {"generation", route->generation},
                                 {"calls", route->scope != "look"}}}};
    }

    json noteEndpoints(const CallerRef& caller, const json& endpoints)
    {
        if (!endpoints.is_array()) return fault("INVALID_ARGUMENT");
        std::uint16_t port = 0;
        for (const auto& e : endpoints)
            if (e.is_object() && e.value("protocol", "") == "tls_tcp" && e.value("port", 0) > 0) {
                port = static_cast<std::uint16_t>(e.value("port", 0));
                break;
            }
        if (!port) return fault("INVALID_ARGUMENT");
        std::lock_guard<std::mutex> lock(m);
        if (caller.name == "core_service") corePort = port;
        else exportStates[caller.name].port = port;
        return json{{"ok", true}};
    }

    json sessionState()
    {
        std::lock_guard<std::mutex> lock(m);
        json generations = json::object();
        for (const auto& e : enrollments.all())
            generations[e.runtimeInstanceId] = routes.generation(e.runtimeInstanceId);
        return json{{"anchors_pem", activeAnchorsLocked()}, {"generations", generations}};
    }

    // ── facade methods (this runtime imports) ───────────────────────────────

    lp_client* linkFor(const std::string& peer, std::string& error)
    {
        if (!ensureControlCredential(error)) return nullptr;
        std::lock_guard<std::mutex> lock(m);
        const auto e = enrollments.find(peer);
        if (!e || e->status != "active") {
            error = "the peer is not paired";
            return nullptr;
        }
        if (!e->controlPort || e->addresses.empty()) {
            error = "the peer's control endpoint is unknown";
            return nullptr;
        }
        auto& link = links[peer];
        if (link && link->client) return link->client;
        link = std::make_unique<Link>();
        link->impl = this;
        link->peer = peer;
        link->client = lp_client_create("peering_control", "peering_module",
                                        R"({"protocol":"tls_tcp"})", nullptr);
        const std::string key = privateKeyPem(controlKey.get());
        if (!link->client
            || lp_client_set_tls_credential(link->client, controlChainPem.c_str(), key.c_str()) != LP_OK
            || lp_client_set_session_hook(link->client, &Impl::linkDialCb, &Impl::linkHelloCb, link.get())
                   != LP_OK) {
            if (link->client) lp_client_destroy(link->client);
            links.erase(peer);
            error = "a control link could not be created";
            return nullptr;
        }
        return link->client;
    }

    static char* linkDialCb(const char*, void* userData)
    {
        auto* link = static_cast<Link*>(userData);
        Impl& impl = *link->impl;
        std::lock_guard<std::mutex> lock(impl.m);
        const auto e = impl.enrollments.find(link->peer);
        if (!e || e->status != "active" || e->subjectPublicKeys.empty())
            return heapCopy(dump(fault("the peer is not paired")));
        return heapCopy(dump(json{{"addresses", e->addresses},
                                  {"port", e->controlPort},
                                  {"server_pin", e->subjectPublicKeys.front()},
                                  {"anchors", e->trustAnchorPem}}));
    }

    static char* linkHelloCb(const char*, void*) { return heapCopy(R"({"purpose":"control"})"); }

    json callPeer(const std::string& peer, const std::string& method, const json& args)
    {
        std::string error;
        lp_client* client = linkFor(peer, error);
        if (!client) return fault("UNREACHABLE: " + error);
        return linkInvoke(client, method, args);
    }

    json requestRoute(const CallerRef& caller, const std::optional<std::string>& consumer,
                      const std::optional<std::int64_t>& timeoutMs)
    {
        (void)timeoutMs;
        if (!consumer || !isValidConsumer(*consumer)) return fault("INVALID_ARGUMENT");
        ImportRule rule;
        std::string clientPin;
        Enrollment peer;
        {
            std::lock_guard<std::mutex> lock(m);
            rule = importsLocked().at(caller.name);
            const auto allowedIt = std::find(rule.allowedCallers.begin(), rule.allowedCallers.end(), *consumer);
            if (*consumer != "runtime" && allowedIt == rule.allowedCallers.end())
                return fault("NOT_AUTHORISED");
            clientPin = facades[caller.name].clientPin;
            const auto e = enrollments.find(rule.from);
            if (!e || e->status != "active") return fault("NOT_PAIRED");
            peer = *e;
        }
        if (clientPin.empty()) return fault("NO_CLIENT_CERTIFICATE");
        json reply = callPeer(rule.from, "establishRoute",
            json::array({{{"consumer", *consumer}, {"target", rule.module}, {"client_pin", clientPin}}}));
        if (isFault(reply) || !reply.is_object()) return isFault(reply) ? reply : fault("MALFORMED_REPLY");
        reply["addresses"] = peer.addresses;
        reply["anchors"] = peer.trustAnchorPem;
        return reply;
    }

    json renewImportRoute(const CallerRef& caller, const std::optional<std::string>& route)
    {
        if (!route) return fault("INVALID_ARGUMENT");
        std::string from;
        {
            std::lock_guard<std::mutex> lock(m);
            from = importsLocked().at(caller.name).from;
        }
        return callPeer(from, "renewRoute", json::array({*route}));
    }

    json importDescriptor(const CallerRef& caller)
    {
        std::lock_guard<std::mutex> lock(m);
        const ImportRule rule = importsLocked().at(caller.name);
        json out = toJson(rule);
        out["name"] = caller.name;
        if (const auto e = enrollments.find(rule.from)) {
            out["peer_alias"] = e->alias;
            out["peer_display_name"] = e->displayName;
        }
        return out;
    }

    json reportImportState(const CallerRef& caller, const std::optional<std::string>& state,
                           const std::optional<std::string>& reason)
    {
        static const std::set<std::string> states = {"connecting", "ready", "error"};
        if (!state || !states.count(*state)) return fault("INVALID_ARGUMENT");
        const std::string why = reason ? reason->substr(0, 512) : std::string();
        {
            std::lock_guard<std::mutex> lock(m);
            FacadeState& f = facades[caller.name];
            if (f.state == *state && f.reason == why) return json{{"ok", true}};
            f.state = *state;
            f.reason = why;
        }
        emit("importStateChanged", json::array({caller.name, *state, why}));
        return json{{"ok", true}};
    }

    // ── management ──────────────────────────────────────────────────────────

    json status()
    {
        const auto s = self();
        const std::uint16_t port = boundControlPort();
        std::lock_guard<std::mutex> lock(m);
        return json{{"runtime_id", s ? s->runtimeId : ""},
                    {"display_id", s ? s->displayId : ""},
                    {"name", config.name},
                    {"configured", configured},
                    {"control", {{"enabled", config.control}, {"port", port}}},
                    {"exports", config.exports},
                    {"operator", config.operatorRoutes},
                    {"peers", enrollments.all().size()},
                    {"pairing_window_ms", windowOpenLocked() ? msUntil(windowUntil) : 0},
                    {"invites", invites.live().size()}};
    }

    json peersDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        json out = json::array();
        for (const auto& e : enrollments.all()) {
            const Cert anchor = certFromPem(e.trustAnchorPem);
            out.push_back({{"runtime_id", e.runtimeInstanceId},
                           {"alias", e.alias},
                           {"display_name", e.displayName},
                           {"display_id", anchor ? displayIdFor(spkiDer(anchor.get())) : ""},
                           {"role", e.role},
                           {"granted_role", e.grantedRole},
                           {"status", e.status},
                           {"addresses", e.addresses},
                           {"control_port", e.controlPort}});
        }
        return json{{"peers", out}};
    }

    json pendingDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        purgeIncomingLocked();
        json out = json::array();
        for (const auto& [id, in] : incoming)
            if (!in.finished && in.responder->revealed()) out.push_back(pendingEntryLocked(id, in));
        for (const auto& [id, o] : outgoing)
            out.push_back({{"id", id},
                           {"direction", "outgoing"},
                           {"code", o->invite ? "" : o->initiator->code()},
                           {"peer_display_id", o->peerDisplayId},
                           {"peer_runtime_id", o->peerRuntimeId},
                           {"state", o->state},
                           {"error", o->error},
                           {"needs_approval", !o->confirmed},
                           {"expires_ms", msUntil(o->expires)}});
        return json{{"pending", out}};
    }

    json routesDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        json served = json::array();
        for (const auto& e : enrollments.all())
            for (const auto& r : routes.forPeer(e.runtimeInstanceId))
                served.push_back({{"route", r.id}, {"peer", r.peer}, {"consumer", r.consumer},
                                  {"target", r.target}, {"expires_ms", msUntil(r.expires)}});
        json imported = json::object();
        for (const auto& [name, f] : facades)
            imported[name] = {{"loaded", f.loaded}, {"state", f.state}, {"reason", f.reason}};
        return json{{"served", served}, {"imports", imported}};
    }

    json exportsDoc()
    {
        std::lock_guard<std::mutex> lock(m);
        json out = json::object();
        for (const auto& [name, rule] : exportsLocked()) {
            const auto state = exportStates.find(name);
            out[name] = {{"events", rule.events},
                         {"locked", config.exportModules.count(name) > 0},
                         {"loaded", state != exportStates.end() && state->second.loaded},
                         {"port", state != exportStates.end() ? state->second.port : 0}};
        }
        return out;
    }

    json openPairingWindow(const std::optional<std::int64_t>& seconds)
    {
        if (!seconds || *seconds < 0) return fault("INVALID_ARGUMENT");
        {
            std::lock_guard<std::mutex> lock(m);
            if (!config.control) return fault("CONTROL_DISABLED");
            const auto s = std::min<std::int64_t>(*seconds, 900);
            windowUntil = SteadyClock::now() + std::chrono::seconds(s);
        }
        refreshControl();
        audit.record("pairing_window", {{"seconds", std::min<std::int64_t>(*seconds, 900)}});
        return json{{"open_ms", std::min<std::int64_t>(*seconds, 900) * 1000}};
    }

    json createInvite(const CallerRef& caller, const std::optional<std::string>& role,
                      const std::optional<std::int64_t>& ttl)
    {
        if (!role || (*role != "peer" && *role != "operator") || !ttl) return fault("INVALID_ARGUMENT");
        const auto s = self();
        if (!s) return fault("IDENTITY_UNAVAILABLE");
        const std::uint16_t port = boundControlPort();
        std::string host;
        {
            std::lock_guard<std::mutex> lock(m);
            if (!config.control || !port) return fault("CONTROL_DISABLED");
            if (*role == "operator" && !config.operatorRoutes) return fault("OPERATOR_DISABLED");
            host = !config.advertise.empty() ? config.advertise
                 : config.controlHost != "0.0.0.0" && config.controlHost != "::" ? config.controlHost
                 : guessAddress();
        }
        if (host.empty()) return fault("NO_ADDRESS: set control.advertise");
        const std::string issuer = caller.kind == CallerRef::Kind::Operator ? "@op:" + caller.name : caller.name;
        const std::string secret = invites.issue(*role, std::chrono::seconds(*ttl), issuer);
        Invite invite;
        invite.runtimeId = s->runtimeId;
        invite.rootDigest = base64url(sha256(s->rootSpki));
        invite.secret = secret;
        invite.host = host;
        invite.port = port;
        refreshControl();
        audit.record("invite_created", {{"role", *role}, {"issued_by", issuer}});
        return json{{"invite", formatInvite(invite)}};
    }

    // Dials `host:port` unanchored and runs pair.hello and pair.reveal.
    json startOutgoing(const std::string& host, std::uint16_t port, const std::optional<Invite>& invite,
                       const std::string& role)
    {
        std::string error;
        if (!ensureControlCredential(error)) return fault("IDENTITY_UNAVAILABLE: " + error);
        const auto s = self();
        if (!s) return fault("IDENTITY_UNAVAILABLE");
        auto o = std::make_unique<Outgoing>();
        o->impl = this;
        o->host = host;
        o->port = port;
        o->invite = invite.has_value();
        o->confirmed = invite.has_value();
        std::string chain;
        std::string key;
        {
            std::lock_guard<std::mutex> lock(m);
            o->initiator = std::make_unique<PairingInitiator>(partyLocked(*s),
                invite ? std::optional<std::string>(invite->secret) : std::nullopt, role);
            if (invite) o->expectedRootDigest = invite->rootDigest;
            chain = controlChainPem;
            key = privateKeyPem(controlKey.get());
        }
        o->client = lp_client_create("peering_control", "peering_module", R"({"protocol":"tls_tcp"})", nullptr);
        if (!o->client || lp_client_set_tls_credential(o->client, chain.c_str(), key.c_str()) != LP_OK
            || lp_client_set_session_hook(o->client, &Impl::pairingDialCb, &Impl::pairingHelloCb, o.get())
                   != LP_OK) {
            if (o->client) lp_client_destroy(o->client);
            return fault("PAIRING_FAILED: no client");
        }
        json hello = o->initiator->hello();
        if (const std::uint16_t own = boundControlPort()) hello["control_port"] = own;
        const auto fail = [&](const std::string& why) {
            lp_client_destroy(o->client);
            audit.record("pairing_failed", {{"host", host}, {"reason", why}});
            return fault("PAIRING_FAILED: " + why);
        };
        const json nonce = linkInvoke(o->client, "pairHello", json::array({hello}));
        if (isFault(nonce)) return fail(nonce["error"].get<std::string>());
        const auto reveal = o->initiator->onNonce(nonce, &error);
        if (!reveal) return fail(error);
        const json revealed = linkInvoke(o->client, "pairReveal", json::array({*reveal}));
        if (isFault(revealed)) return fail(revealed["error"].get<std::string>());
        o->id = base64url(randomBytes(12));
        o->expires = SteadyClock::now() + kPairingLifetime;
        o->state = o->confirmed ? "confirming" : "code";
        json out = {{"id", o->id},
                    {"code", o->invite ? "" : o->initiator->code()},
                    {"peer_display_id", o->peerDisplayId},
                    {"state", o->state}};
        {
            std::lock_guard<std::mutex> lock(m);
            outgoing[o->id] = std::move(o);
        }
        wake.notify_all();
        return out;
    }

    static char* pairingDialCb(const char*, void* userData)
    {
        auto* o = static_cast<Outgoing*>(userData);
        return heapCopy(dump(json{{"addresses", {o->host}}, {"port", o->port}, {"unanchored", true}}));
    }

    static char* pairingHelloCb(const char* request, void* userData)
    {
        auto* o = static_cast<Outgoing*>(userData);
        const auto doc = json::parse(request ? request : "", nullptr, false);
        if (o->transportSeen || !doc.is_object())
            return heapCopy(dump(fault("the pairing connection was lost")));
        const auto chain = presentedChain(doc.value("peer_chain", json()), Role::Control);
        const auto exporter = fromBase64url(doc.value("exporter", ""));
        if (!chain || !exporter || exporter->size() != 32)
            return heapCopy(dump(fault("the peer presented no control certificate")));
        if (!o->expectedRootDigest.empty() && base64url(sha256(chain->rootSpki)) != o->expectedRootDigest)
            return heapCopy(dump(fault("the peer is not the runtime the invite names")));
        o->transportSeen = true;
        o->initiator->setTransport(chain->rootSpki, *exporter);
        o->peerRootPem = certPem(chain->root.get());
        o->peerLeafPin = spkiPin(chain->leafSpki);
        o->peerDisplayId = displayIdFor(chain->rootSpki);
        return heapCopy(R"({"purpose":"pairing"})");
    }

    json pairWith(const std::optional<std::string>& host, const std::optional<std::int64_t>& port)
    {
        if (!host || host->empty() || !port || *port <= 0 || *port > 65535) return fault("INVALID_ARGUMENT");
        return startOutgoing(*host, static_cast<std::uint16_t>(*port), std::nullopt, "peer");
    }

    json redeemInvite(const std::optional<std::string>& text)
    {
        if (!text) return fault("INVALID_ARGUMENT");
        std::string error;
        const auto invite = parseInvite(*text, &error);
        if (!invite) return fault("INVALID_INVITE: " + error);
        {
            std::lock_guard<std::mutex> lock(m);
            if (enrollments.find(invite->runtimeId)) return fault("ALREADY_PAIRED");
        }
        return startOutgoing(invite->host, invite->port, invite, "operator");
    }

    json decidePairing(const std::optional<std::string>& id, bool accept)
    {
        if (!id) return fault("INVALID_ARGUMENT");
        {
            std::lock_guard<std::mutex> lock(m);
            if (const auto it = incoming.find(*id); it != incoming.end() && !it->second.finished) {
                if (accept) it->second.responder->approve();
                else it->second.responder->reject();
                audit.record(accept ? "pairing_approved" : "pairing_rejected",
                             {{"peer", it->second.responder->initiatorRuntimeId()}});
                return json{{"ok", true}};
            }
            if (const auto it = outgoing.find(*id); it != outgoing.end()) {
                Outgoing& o = *it->second;
                if (o.state != "code") return fault("NOT_PENDING");
                if (accept) {
                    o.confirmed = true;
                    o.state = "confirming";
                } else {
                    o.state = "failed";
                    o.error = "rejected here";
                }
            } else {
                return fault("NO_SUCH_PAIRING");
            }
        }
        wake.notify_all();
        return json{{"ok", true}};
    }

    std::optional<std::string> resolvePeerLocked(const std::string& peerOrAlias) const
    {
        if (enrollments.find(peerOrAlias)) return peerOrAlias;
        if (const auto e = enrollments.findByAlias(peerOrAlias)) return e->runtimeInstanceId;
        return std::nullopt;
    }

    json removePeer(const std::optional<std::string>& peerArg)
    {
        if (!peerArg) return fault("INVALID_ARGUMENT");
        std::string peer;
        std::unique_ptr<Link> link;
        std::uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(m);
            const auto resolved = resolvePeerLocked(*peerArg);
            if (!resolved) return fault("NO_SUCH_PEER");
            peer = *resolved;
            enrollments.remove(peer);
            std::string error;
            if (!enrollments.save(&error)) return fault("FAILED: " + error);
            generation = routes.revokePeer(peer);
            if (const auto it = links.find(peer); it != links.end()) {
                link = std::move(it->second);
                links.erase(it);
            }
        }
        if (link && link->client) lp_client_destroy(link->client);
        audit.record("peer_removed", {{"peer", peer}});
        refreshControl();
        emit("routesRevoked", json::array({peer, static_cast<std::int64_t>(generation)}));
        emit("peersChanged");
        emit("anchorsChanged");
        emit("importsChanged");
        return json{{"ok", true}, {"generation", generation}};
    }

    json renamePeer(const std::optional<std::string>& peerArg, const std::optional<std::string>& alias)
    {
        if (!peerArg || !alias || !isValidAlias(*alias)) return fault("INVALID_ARGUMENT");
        {
            std::lock_guard<std::mutex> lock(m);
            const auto resolved = resolvePeerLocked(*peerArg);
            if (!resolved) return fault("NO_SUCH_PEER");
            Enrollment e = *enrollments.find(*resolved);
            e.alias = *alias;
            ++e.revision;
            std::string error;
            if (!enrollments.update(e, &error) || !enrollments.save(&error)) {
                enrollments.load();
                return fault("FAILED: " + error);
            }
        }
        emit("peersChanged");
        return json{{"ok", true}};
    }

    json setExport(const std::optional<std::string>& module, const json& rule)
    {
        if (!module || !isValidModuleName(*module) || isReservedName(*module)) return fault("INVALID_ARGUMENT");
        std::string error;
        const auto parsed = parseExportRule(rule, &error);
        if (!parsed) return fault("INVALID_ARGUMENT: " + error);
        {
            std::lock_guard<std::mutex> lock(m);
            if (config.exportModules.count(*module)) return fault("LOCKED");
            if (importsLocked().count(*module)) return fault("IMPORTED_UNDER_THAT_NAME");
            localExports[*module] = *parsed;
            saveLocalLocked();
        }
        audit.record("export_set", {{"module", *module}});
        emit("exportsChanged");
        return json{{"ok", true}};
    }

    json removeExport(const std::optional<std::string>& module)
    {
        if (!module) return fault("INVALID_ARGUMENT");
        {
            std::lock_guard<std::mutex> lock(m);
            if (config.exportModules.count(*module)) return fault("LOCKED");
            if (!localExports.erase(*module)) return fault("NOT_EXPORTED");
            saveLocalLocked();
            for (const auto& route : routes.forTarget(*module)) routes.remove(route.id);
        }
        audit.record("export_removed", {{"module", *module}});
        emit("exportsChanged");
        return json{{"ok", true}};
    }

    json setImport(const std::optional<std::string>& name, const json* rule)
    {
        if (!name || !rule) return fault("INVALID_ARGUMENT");
        std::string error;
        const auto parsed = parseImportRule(*name, *rule, &error);
        if (!parsed) return fault("INVALID_ARGUMENT: " + error);
        {
            std::lock_guard<std::mutex> lock(m);
            if (config.imports.count(*name)) return fault("LOCKED");
            if (exportsLocked().count(*name)) return fault("EXPORTED_UNDER_THAT_NAME");
            const auto e = enrollments.find(parsed->from);
            if (!e) return fault("NOT_PAIRED");
            localImports[*name] = *parsed;
            saveLocalLocked();
        }
        audit.record("import_set", {{"name", *name}, {"from", parsed->from}, {"module", parsed->module}});
        emit("importsChanged");
        return json{{"ok", true}};
    }

    json removeImport(const std::optional<std::string>& name)
    {
        if (!name) return fault("INVALID_ARGUMENT");
        {
            std::lock_guard<std::mutex> lock(m);
            if (config.imports.count(*name)) return fault("LOCKED");
            if (!localImports.erase(*name)) return fault("NOT_IMPORTED");
            saveLocalLocked();
        }
        audit.record("import_removed", {{"name", *name}});
        emit("importsChanged");
        return json{{"ok", true}};
    }

    json setPolicy(const json* doc)
    {
        if (!doc) return fault("INVALID_ARGUMENT");
        for (const auto& item : doc->items()) {
            const auto slash = item.key().find('/');
            if (slash == std::string::npos || !isUuid(item.key().substr(0, slash)))
                return fault("INVALID_ARGUMENT: keys are <runtime id>/<consumer> or <runtime id>/*");
            const std::string consumer = item.key().substr(slash + 1);
            if (consumer != "*" && !isValidConsumer(consumer)) return fault("INVALID_ARGUMENT: " + item.key());
            if (!item.value().is_array()) return fault("INVALID_ARGUMENT: " + item.key());
            for (const auto& target : item.value())
                if (!target.is_string() || !isValidModuleName(target.get<std::string>())
                    || isReservedName(target.get<std::string>()))
                    return fault("INVALID_ARGUMENT: " + item.key());
        }
        {
            std::lock_guard<std::mutex> lock(m);
            policy = *doc;
            saveLocalLocked();
        }
        audit.record("policy_set", {{"entries", doc->size()}});
        emit("remotePolicyChanged");
        return json{{"ok", true}};
    }

    // ── background work ─────────────────────────────────────────────────────

    void run()
    {
        std::unique_lock<std::mutex> lock(m);
        bool admitted = false;
        while (!stopping) {
            wake.wait_for(lock, options.tick);
            if (stopping) break;
            purgeIncomingLocked();
            std::vector<Outgoing*> due;
            const auto now = SteadyClock::now();
            for (auto it = outgoing.begin(); it != outgoing.end();) {
                Outgoing& o = *it->second;
                const bool done = o.state == "paired" || o.state == "failed";
                if (done && o.expires <= now) {
                    if (o.client) lp_client_destroy(o.client);
                    it = outgoing.erase(it);
                    continue;
                }
                if (!done && o.expires <= now) {
                    o.state = "failed";
                    o.error = "timed out";
                    o.expires = now + kFinishedKept;
                }
                if (o.state == "confirming" && !o.polling) {
                    o.polling = true;
                    due.push_back(&o);
                }
                ++it;
            }
            const bool admit = windowOpenLocked() || invites.anyLive();
            const bool refresh = admit != admitted;
            admitted = admit;
            lock.unlock();
            for (Outgoing* o : due) poll(*o);
            refreshLocalInvite();
            if (refresh) refreshControl();
            lock.lock();
        }
    }

    // One pair.confirm; enrolls the peer once it accepts.
    void poll(Outgoing& o)
    {
        const json result = linkInvoke(o.client, "pairConfirm", json::array({o.initiator->confirm()}));
        std::string error;
        bool enrolled = false;
        {
            std::lock_guard<std::mutex> lock(m);
            o.polling = false;
            if (o.state != "confirming") return;
            if (isFault(result)) {
                o.state = "failed";
                o.error = result["error"].get<std::string>();
            } else if (result.value("status", "") == "waiting") {
                return;
            } else if (const auto outcome = o.initiator->onResult(result, &error)) {
                Enrollment e;
                e.runtimeInstanceId = outcome->peerRuntimeId;
                e.trustAnchorPem = o.peerRootPem;
                e.subjectPublicKeys = {o.peerLeafPin};
                e.alias = uniqueAliasLocked(outcome->peerDisplayName);
                e.role = "peer";
                e.grantedRole = outcome->role;
                e.displayName = outcome->peerDisplayName;
                e.addresses = {o.host};
                e.controlPort = o.port;
                if (enrollments.add(e, &error) && enrollments.save(&error)) {
                    o.state = "paired";
                    o.peerRuntimeId = e.runtimeInstanceId;
                    enrolled = true;
                    audit.record("paired", {{"peer", e.runtimeInstanceId}, {"granted_role", e.grantedRole},
                                            {"direction", "outgoing"}});
                } else {
                    enrollments.load();
                    o.state = "failed";
                    o.error = error;
                }
            } else {
                o.state = "failed";
                o.error = error;
            }
            o.expires = SteadyClock::now() + kFinishedKept;
        }
        if (enrolled) {
            refreshControl();
            emit("peersChanged");
            emit("anchorsChanged");
        }
    }

    Options options;
    mutable std::mutex m;
    std::mutex writeMutex;
    std::condition_variable wake;
    std::thread worker;
    bool stopping = false;

    PeeringConfig config;
    bool configured = false;
    std::optional<Self> identity;
    Bytes announceKey;
    PKey controlKey;
    std::string controlChainPem;
    std::string controlLeafPin;
    SteadyClock::time_point controlLeafExpires{};
    lp_provider* control = nullptr;
    std::string controlHost;
    std::uint16_t controlPortWanted = 0;
    SteadyClock::time_point windowUntil{};
    std::string localInviteDigest;

    EnrollmentStore enrollments;
    InviteStore invites;
    TicketStore tickets;
    RouteTable routes;
    AuditLog audit;

    std::map<std::string, ExportRule> localExports;
    std::map<std::string, ImportRule> localImports;
    json policy = json::object();

    std::map<std::string, ExportState> exportStates;
    std::map<std::string, FacadeState> facades;
    std::uint16_t corePort = 0;
    std::string corePin;

    std::map<std::string, Incoming> incoming;
    std::map<std::string, std::unique_ptr<Outgoing>> outgoing;
    std::map<std::string, std::unique_ptr<Link>> links;
};

PeeringService::PeeringService(Options options) : impl_(std::make_shared<Impl>(std::move(options)))
{
    std::string error;
    if (!impl_->start(error)) throw std::runtime_error("peering state: " + error);
}

PeeringService::~PeeringService() { impl_->shutdown(); }

json PeeringService::invoke(const CallerRef& caller, const std::string& method, const json& args)
{
    try {
        return impl_->invoke(caller, method, args.is_array() ? args : json::array());
    } catch (...) {
        return fault("FAILED");
    }
}

std::uint16_t PeeringService::controlPort() const { return impl_->boundControlPort(); }

} // namespace logos::peering
