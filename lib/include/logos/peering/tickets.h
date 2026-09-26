#pragma once

// One-shot route tickets (spec: logos.route-ticket.random-256). The store keeps
// only a BLAKE3 digest of each ticket, never the ticket itself.

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace logos::peering {

class TicketStore {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;

    static constexpr std::chrono::seconds kMaxTtl{60};

    // `ttl` is clamped to kMaxTtl.
    explicit TicketStore(std::chrono::seconds ttl = kMaxTtl, Now now = {});

    // Returns a fresh 256-bit ticket (base64url) bound to `record`.
    std::string mint(nlohmann::json record);

    // Consumes the ticket on every attempt. Returns its record only when it was
    // live and `accept` (if given) approves the record.
    std::optional<nlohmann::json> redeem(const std::string& ticket,
                                         const std::function<bool(const nlohmann::json&)>& accept = {});

    std::size_t live();

    static std::string digestOf(const std::string& ticket);

private:
    struct Entry {
        nlohmann::json record;
        Clock::time_point expires;
    };

    void purgeLocked(Clock::time_point now);

    std::chrono::seconds ttl_;
    Now now_;
    std::mutex mutex_;
    std::map<std::string, Entry> byDigest_;
};

} // namespace logos::peering
