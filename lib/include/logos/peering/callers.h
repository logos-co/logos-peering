#pragma once

// Caller documents: parsing them strictly and mapping them to the consumer name
// a facade vouches for, or to the principal a remote session binds.

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace logos::peering {

// Parses a JSON object; a duplicate key anywhere makes the whole text invalid.
std::optional<nlohmann::json> parseStrictObject(const std::string& text);

// The consumer a facade names upstream for a local caller (plan R7):
// {kind:module,name:X} -> X; {kind:host} -> "runtime"; {kind:operator,name:N} -> "@op:N".
std::optional<std::string> consumerForCaller(const nlohmann::json& caller);
std::optional<std::string> consumerForCallerJson(const std::string& callerJson);

// A consumer name as it may travel between runtimes.
bool isValidConsumer(const std::string& consumer);

// What a provider sees for a remote consumer, and for a remote operator.
nlohmann::json remotePrincipal(const std::string& peerRuntimeId, const std::string& consumer);
nlohmann::json remoteOperatorPrincipal(const std::string& peerRuntimeId);

} // namespace logos::peering
