#include "logos/peering/discovery_key.h"

namespace logos::peering {
namespace {

Bytes tag(const Bytes& key, const char* label, std::uint64_t epoch, const std::string& extra)
{
    Bytes input = toBytes(label);
    appendBe64(input, epoch);
    appendFramed(input, toBytes(extra));
    return hmacSha256(key, input);
}

} // namespace

std::uint64_t discoveryEpoch(std::chrono::system_clock::time_point when)
{
    const auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(when.time_since_epoch()).count();
    return seconds <= 0 ? 0 : static_cast<std::uint64_t>(seconds) / kDiscoveryEpoch.count();
}

std::string discoveryRid(const Bytes& announceKey, std::uint64_t epoch)
{
    Bytes mac = tag(announceKey, "logos-rid-v1", epoch, {});
    mac.resize(16);
    return base64url(mac);
}

bool discoveryRidMatches(const Bytes& announceKey, const std::string& rid, std::uint64_t epoch)
{
    const auto presented = fromBase64url(rid);
    if (!presented || presented->size() != 16) return false;
    bool matched = false;
    for (std::uint64_t e = epoch == 0 ? 0 : epoch - 1; e <= epoch + 1; ++e) {
        const auto expected = fromBase64url(discoveryRid(announceKey, e));
        matched = (expected && constantTimeEqual(*expected, *presented)) || matched;
    }
    return matched;
}

std::string discoveryLabel(const Bytes& announceKey, std::uint64_t epoch, const std::string& purpose)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    const Bytes mac = tag(announceKey, "logos-label-v1", epoch, purpose);
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (std::size_t i = 0; i < 10; ++i) {
        acc = ((acc << 8) | mac[i]) & 0xFFFFu;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(alphabet[(acc >> bits) & 31u]);
        }
    }
    return out;
}

} // namespace logos::peering
