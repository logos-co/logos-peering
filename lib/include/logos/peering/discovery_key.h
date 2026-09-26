#pragma once

// Rotating discovery tags. A runtime announces rid = HMAC(announce key, epoch);
// only peers holding its announce key can recognise it, and the tag changes
// every epoch, so a passive observer cannot follow the runtime.

#include "logos/peering/crypto.h"

#include <chrono>
#include <cstdint>
#include <string>

namespace logos::peering {

inline constexpr std::chrono::seconds kDiscoveryEpoch{900};

std::uint64_t discoveryEpoch(std::chrono::system_clock::time_point when);

// 16 bytes of HMAC-SHA-256, base64url (22 characters).
std::string discoveryRid(const Bytes& announceKey, std::uint64_t epoch);

// Accepts the epoch before and after `epoch` too, for clock skew.
bool discoveryRidMatches(const Bytes& announceKey, const std::string& rid, std::uint64_t epoch);

// A DNS-safe label (16 lowercase base32 characters) for `purpose` in `epoch`.
std::string discoveryLabel(const Bytes& announceKey, std::uint64_t epoch, const std::string& purpose);

} // namespace logos::peering
