#pragma once

// Append-only audit trail (JSON lines, 0600). Denials and evaluation failures
// are distinct events, as the spec asks.

#include <nlohmann/json.hpp>

#include <filesystem>
#include <mutex>
#include <string>

namespace logos::peering {

class AuditLog {
public:
    explicit AuditLog(std::filesystem::path file);

    // Adds "ts" (RFC 3339, UTC) and "event" to `fields` and appends the line.
    void record(const std::string& event, nlohmann::json fields = nlohmann::json::object());

private:
    std::filesystem::path file_;
    std::mutex mutex_;
};

} // namespace logos::peering
