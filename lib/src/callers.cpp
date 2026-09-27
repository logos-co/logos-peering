#include "logos/peering/callers.h"

#include "logos/peering/identity.h"
#include "logos/peering/names.h"

#include <set>
#include <vector>

namespace logos::peering {

std::optional<nlohmann::json> parseStrictObject(const std::string& text)
{
    // One key set per open object; a repeated key poisons the parse.
    std::vector<std::set<std::string>> keys;
    bool duplicate = false;
    auto callback = [&](int depth, nlohmann::json::parse_event_t event, nlohmann::json& parsed) {
        (void)depth;
        switch (event) {
        case nlohmann::json::parse_event_t::object_start:
            keys.emplace_back();
            break;
        case nlohmann::json::parse_event_t::object_end:
            if (!keys.empty()) keys.pop_back();
            break;
        case nlohmann::json::parse_event_t::key:
            if (!keys.empty() && !keys.back().insert(parsed.get<std::string>()).second) duplicate = true;
            break;
        default:
            break;
        }
        return true;
    };
    nlohmann::json value = nlohmann::json::parse(text, callback, false);
    if (duplicate || value.is_discarded() || !value.is_object()) return std::nullopt;
    return value;
}

std::optional<std::string> consumerForCaller(const nlohmann::json& caller)
{
    if (!caller.is_object()) return std::nullopt;
    const auto kind = caller.find("kind");
    if (kind == caller.end() || !kind->is_string()) return std::nullopt;
    const auto name = caller.find("name");
    const std::string nameText = name != caller.end() && name->is_string() ? name->get<std::string>() : "";
    if (*kind == "module" && isValidModuleName(nameText)) return nameText;
    if (*kind == "host") return std::string("runtime");
    if (*kind == "operator" && isValidModuleName(nameText)) return "@op:" + nameText;
    return std::nullopt;
}

std::optional<std::string> consumerForCallerJson(const std::string& callerJson)
{
    const auto caller = parseStrictObject(callerJson);
    return caller ? consumerForCaller(*caller) : std::nullopt;
}

bool isValidConsumer(const std::string& consumer)
{
    if (consumer == "runtime") return true;
    if (consumer.rfind("@op:", 0) == 0) return isValidModuleName(consumer.substr(4));
    return isValidModuleName(consumer);
}

nlohmann::json remotePrincipal(const std::string& peerRuntimeId, const std::string& consumer)
{
    return {{"kind", "remote"}, {"peer", peerRuntimeId}, {"name", consumer}};
}

} // namespace logos::peering
