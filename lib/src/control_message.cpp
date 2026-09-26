#include "logos/peering/control_message.h"

#include "logos/peering/callers.h"

namespace logos::peering {

std::vector<std::uint8_t> encodeControlFrame(const nlohmann::json& message)
{
    const std::string text = message.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::vector<std::uint8_t> frame;
    frame.reserve(text.size() + 4);
    const auto size = static_cast<std::uint32_t>(text.size());
    for (int shift = 24; shift >= 0; shift -= 8)
        frame.push_back(static_cast<std::uint8_t>((size >> shift) & 0xFFu));
    frame.insert(frame.end(), text.begin(), text.end());
    return frame;
}

void ControlFrameDecoder::feed(const std::uint8_t* data, std::size_t size)
{
    if (failed()) return;
    buffer_.insert(buffer_.end(), data, data + size);
}

std::optional<nlohmann::json> ControlFrameDecoder::next()
{
    if (failed() || buffer_.size() < 4) return std::nullopt;
    const std::uint32_t size = (static_cast<std::uint32_t>(buffer_[0]) << 24)
                               | (static_cast<std::uint32_t>(buffer_[1]) << 16)
                               | (static_cast<std::uint32_t>(buffer_[2]) << 8) | buffer_[3];
    if (size == 0 || size > limit_) {
        error_ = "control frame of " + std::to_string(size) + " bytes is over the limit";
        buffer_.clear();
        return std::nullopt;
    }
    if (buffer_.size() < 4u + size) return std::nullopt;
    const std::string text(buffer_.begin() + 4, buffer_.begin() + 4 + size);
    buffer_.erase(buffer_.begin(), buffer_.begin() + 4 + size);
    auto message = parseStrictObject(text);
    if (!message) {
        error_ = "control frame is not a JSON object with unique keys";
        buffer_.clear();
        return std::nullopt;
    }
    return message;
}

nlohmann::json controlRequest(std::uint64_t id, const std::string& type, nlohmann::json body)
{
    return {{"id", id}, {"type", type}, {"body", std::move(body)}};
}

nlohmann::json controlReply(std::uint64_t id, nlohmann::json body)
{
    return {{"id", id}, {"ok", true}, {"body", std::move(body)}};
}

nlohmann::json controlError(std::uint64_t id, const std::string& error)
{
    return {{"id", id}, {"ok", false}, {"error", error}};
}

nlohmann::json controlPush(const std::string& type, nlohmann::json body)
{
    return {{"type", type}, {"body", std::move(body)}};
}

} // namespace logos::peering
