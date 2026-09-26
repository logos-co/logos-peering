#pragma once

// The provider side's routes and sessions. A route is what establishRoute
// granted; a session is a connection that redeemed a route's ticket, keyed by
// its TLS exporter so a retry on the same connection is idempotent.

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

struct Route {
    std::string id;
    std::string peer;      // the consuming runtime's UUID
    std::string consumer;  // module name, "runtime" or "@op:<name>"
    std::string target;    // exported module, or core_service for operator routes
    std::string scope;     // "calls" | "runtime"
    std::string clientPin; // the facade's client leaf
    std::string ticketDigest;
    std::uint64_t endpointEpoch = 0;
    std::uint64_t generation = 0;
    std::chrono::steady_clock::time_point expires;
};

class RouteTable {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;

    explicit RouteTable(Now now = {});

    // Assigns the id and the peer's current generation.
    Route add(Route route, std::chrono::seconds lifetime);
    std::optional<Route> find(const std::string& id);
    bool attachTicket(const std::string& id, const std::string& ticketDigest);
    // Extends a live route of `peer`; returns the new remaining lifetime.
    std::optional<std::chrono::seconds> renew(const std::string& id, const std::string& peer,
                                              std::chrono::seconds lifetime);
    // Drops every route of `peer` and returns its new generation.
    std::uint64_t revokePeer(const std::string& peer);
    std::uint64_t generation(const std::string& peer);
    std::vector<Route> forPeer(const std::string& peer);
    std::vector<Route> forTarget(const std::string& target);
    bool remove(const std::string& id);

    // Records that the connection with `exporter` redeemed `routeId`. A second
    // binding of the same exporter must name the same route.
    bool bindSession(const std::string& exporter, const std::string& routeId);
    std::optional<std::string> sessionRoute(const std::string& exporter);

private:
    void purgeLocked(Clock::time_point now);

    Now now_;
    std::mutex mutex_;
    std::map<std::string, Route> routes_;
    std::map<std::string, std::uint64_t> generations_;
    std::map<std::string, std::string> sessions_;
};

} // namespace logos::peering
