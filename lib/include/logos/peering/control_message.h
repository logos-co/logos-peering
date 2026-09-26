#pragma once

// Control-link frames: a 4-byte big-endian length, then one JSON object.
//   request  {"id": n, "type": "<type>", "body": {...}}
//   reply    {"id": n, "ok": true, "body": {...}} | {"id": n, "ok": false, "error": "..."}
//   push     {"type": "<type>", "body": {...}}  (no id; no reply)
// Frames before a link is authenticated are capped much lower than after.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

inline constexpr std::size_t kPreAuthFrameLimit = 4 * 1024;
inline constexpr std::size_t kControlFrameLimit = 64 * 1024;

std::vector<std::uint8_t> encodeControlFrame(const nlohmann::json& message);

// Accumulates bytes and yields whole frames. A frame over the limit, or one
// that is not a JSON object with unique keys, puts the decoder in error.
class ControlFrameDecoder {
public:
    explicit ControlFrameDecoder(std::size_t limit = kPreAuthFrameLimit) : limit_(limit) {}

    void setLimit(std::size_t limit) { limit_ = limit; }
    void feed(const std::uint8_t* data, std::size_t size);
    std::optional<nlohmann::json> next();
    bool failed() const { return !error_.empty(); }
    const std::string& error() const { return error_; }

private:
    std::size_t limit_;
    std::vector<std::uint8_t> buffer_;
    std::string error_;
};

nlohmann::json controlRequest(std::uint64_t id, const std::string& type, nlohmann::json body);
nlohmann::json controlReply(std::uint64_t id, nlohmann::json body);
nlohmann::json controlError(std::uint64_t id, const std::string& error);
nlohmann::json controlPush(const std::string& type, nlohmann::json body);

} // namespace logos::peering
