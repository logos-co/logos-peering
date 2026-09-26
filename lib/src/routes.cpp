#include "logos/peering/routes.h"

#include "logos/peering/crypto.h"

namespace logos::peering {

RouteTable::RouteTable(Now now) : now_(now ? std::move(now) : Now([] { return Clock::now(); })) {}

Route RouteTable::add(Route route, std::chrono::seconds lifetime)
{
    const Clock::time_point now = now_();
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now);
    route.id = base64url(randomBytes(16));
    route.generation = generations_[route.peer];
    route.expires = now + lifetime;
    routes_[route.id] = route;
    return route;
}

std::optional<Route> RouteTable::find(const std::string& id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    const auto it = routes_.find(id);
    if (it == routes_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::chrono::seconds> RouteTable::renew(const std::string& id, const std::string& peer,
                                                      std::chrono::seconds lifetime)
{
    const Clock::time_point now = now_();
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now);
    const auto it = routes_.find(id);
    if (it == routes_.end() || it->second.peer != peer) return std::nullopt;
    it->second.expires = now + lifetime;
    return lifetime;
}

std::uint64_t RouteTable::revokePeer(const std::string& peer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = routes_.begin(); it != routes_.end();) {
        if (it->second.peer != peer) {
            ++it;
            continue;
        }
        for (auto s = sessions_.begin(); s != sessions_.end();)
            s = s->second == it->first ? sessions_.erase(s) : std::next(s);
        it = routes_.erase(it);
    }
    return ++generations_[peer];
}

std::uint64_t RouteTable::generation(const std::string& peer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return generations_[peer];
}

std::vector<Route> RouteTable::forPeer(const std::string& peer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    std::vector<Route> out;
    for (const auto& [id, route] : routes_)
        if (route.peer == peer) out.push_back(route);
    return out;
}

std::vector<Route> RouteTable::forTarget(const std::string& target)
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    std::vector<Route> out;
    for (const auto& [id, route] : routes_)
        if (route.target == target) out.push_back(route);
    return out;
}

bool RouteTable::remove(const std::string& id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto s = sessions_.begin(); s != sessions_.end();)
        s = s->second == id ? sessions_.erase(s) : std::next(s);
    return routes_.erase(id) > 0;
}

bool RouteTable::bindSession(const std::string& exporter, const std::string& routeId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    if (!routes_.count(routeId)) return false;
    const auto [it, inserted] = sessions_.emplace(exporter, routeId);
    return inserted || it->second == routeId;
}

std::optional<std::string> RouteTable::sessionRoute(const std::string& exporter)
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    const auto it = sessions_.find(exporter);
    if (it == sessions_.end()) return std::nullopt;
    return it->second;
}

void RouteTable::purgeLocked(Clock::time_point now)
{
    for (auto it = routes_.begin(); it != routes_.end();) {
        if (it->second.expires > now) {
            ++it;
            continue;
        }
        for (auto s = sessions_.begin(); s != sessions_.end();)
            s = s->second == it->first ? sessions_.erase(s) : std::next(s);
        it = routes_.erase(it);
    }
}

} // namespace logos::peering
