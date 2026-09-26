#include "logos/peering/tickets.h"

#include "logos/peering/crypto.h"

#include <algorithm>

namespace logos::peering {

TicketStore::TicketStore(std::chrono::seconds ttl, Now now)
    : ttl_(std::clamp(ttl, std::chrono::seconds(1), kMaxTtl))
    , now_(now ? std::move(now) : Now([] { return Clock::now(); }))
{
}

std::string TicketStore::digestOf(const std::string& ticket)
{
    const auto raw = fromBase64url(ticket);
    if (!raw || raw->size() != 32) return {};
    return base64url(blake3(*raw));
}

std::string TicketStore::mint(nlohmann::json record)
{
    const std::string ticket = base64url(randomBytes(32));
    const Clock::time_point now = now_();
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now);
    byDigest_[digestOf(ticket)] = Entry{std::move(record), now + ttl_};
    return ticket;
}

std::optional<nlohmann::json> TicketStore::redeem(
    const std::string& ticket, const std::function<bool(const nlohmann::json&)>& accept)
{
    const std::string digest = digestOf(ticket);
    if (digest.empty()) return std::nullopt;
    const Clock::time_point now = now_();
    Entry entry;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = byDigest_.find(digest);
        if (it == byDigest_.end()) return std::nullopt;
        entry = std::move(it->second);
        byDigest_.erase(it);
    }
    if (entry.expires <= now) return std::nullopt;
    if (accept && !accept(entry.record)) return std::nullopt;
    return entry.record;
}

std::size_t TicketStore::live()
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked(now_());
    return byDigest_.size();
}

void TicketStore::purgeLocked(Clock::time_point now)
{
    for (auto it = byDigest_.begin(); it != byDigest_.end();)
        it = it->second.expires <= now ? byDigest_.erase(it) : std::next(it);
}

} // namespace logos::peering
