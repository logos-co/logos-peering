#include "logos/peering/invites.h"

#include "logos/peering/crypto.h"
#include "logos/peering/identity.h"

#include <cctype>

namespace logos::peering {
namespace {

constexpr const char* kPrefix = "logos-pair:v1:";

void setError(std::string* error, const std::string& text)
{
    if (error) *error = text;
}

bool isDigest(const std::string& text)
{
    const auto raw = fromBase64url(text);
    return raw && raw->size() == 32 && base64url(*raw) == text;
}

bool isDnsName(const std::string& host)
{
    if (host.empty() || host.size() > 253) return false;
    std::size_t labelLength = 0;
    for (std::size_t i = 0; i < host.size(); ++i) {
        const char c = host[i];
        if (c == '.') {
            if (labelLength == 0 || host[i - 1] == '-') return false;
            labelLength = 0;
            continue;
        }
        const bool alnum = std::isalnum(static_cast<unsigned char>(c)) != 0;
        if (!alnum && c != '-') return false;
        if (labelLength == 0 && c == '-') return false;
        if (++labelLength > 63) return false;
    }
    return labelLength > 0 && host.back() != '-';
}

bool isIpv6Literal(const std::string& host)
{
    if (host.size() < 2 || host.size() > 45) return false;
    for (const char c : host)
        if (!std::isxdigit(static_cast<unsigned char>(c)) && c != ':' && c != '.') return false;
    return host.find(':') != std::string::npos;
}

} // namespace

std::string formatInvite(const Invite& invite)
{
    const bool v6 = invite.host.find(':') != std::string::npos;
    const std::string host = v6 ? "[" + invite.host + "]" : invite.host;
    return std::string(kPrefix) + invite.runtimeId + ":" + invite.rootDigest + ":" + invite.secret
           + "@" + host + ":" + std::to_string(invite.port);
}

std::optional<Invite> parseInvite(const std::string& raw, std::string* error)
{
    std::string text = raw;
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(0, 1);
    if (text.rfind(kPrefix, 0) != 0) {
        setError(error, "not a logos-pair:v1 invite");
        return std::nullopt;
    }
    const std::string body = text.substr(std::string(kPrefix).size());
    const std::size_t at = body.find('@');
    if (at == std::string::npos) {
        setError(error, "the invite has no address");
        return std::nullopt;
    }
    const std::string credentials = body.substr(0, at);
    const std::string address = body.substr(at + 1);

    Invite invite;
    const std::size_t first = credentials.find(':');
    const std::size_t second = first == std::string::npos ? first : credentials.find(':', first + 1);
    if (second == std::string::npos || credentials.find(':', second + 1) != std::string::npos) {
        setError(error, "the invite must carry a runtime id, a root digest and a secret");
        return std::nullopt;
    }
    invite.runtimeId = credentials.substr(0, first);
    invite.rootDigest = credentials.substr(first + 1, second - first - 1);
    invite.secret = credentials.substr(second + 1);
    if (!isUuid(invite.runtimeId) || !isDigest(invite.rootDigest) || !isDigest(invite.secret)) {
        setError(error, "the invite's runtime id, root digest or secret is malformed");
        return std::nullopt;
    }

    std::string portText;
    if (!address.empty() && address.front() == '[') {
        const std::size_t close = address.find(']');
        if (close == std::string::npos || close + 1 >= address.size() || address[close + 1] != ':') {
            setError(error, "the invite's IPv6 address is malformed");
            return std::nullopt;
        }
        invite.host = address.substr(1, close - 1);
        portText = address.substr(close + 2);
        if (!isIpv6Literal(invite.host)) {
            setError(error, "the invite's IPv6 address is malformed");
            return std::nullopt;
        }
    } else {
        const std::size_t colon = address.rfind(':');
        if (colon == std::string::npos) {
            setError(error, "the invite has no port");
            return std::nullopt;
        }
        invite.host = address.substr(0, colon);
        portText = address.substr(colon + 1);
        if (!isDnsName(invite.host)) {
            setError(error, "the invite's host is malformed");
            return std::nullopt;
        }
    }
    if (portText.empty() || portText.size() > 5) {
        setError(error, "the invite's port is malformed");
        return std::nullopt;
    }
    unsigned long port = 0;
    for (const char c : portText) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            setError(error, "the invite's port is malformed");
            return std::nullopt;
        }
        port = port * 10 + static_cast<unsigned long>(c - '0');
    }
    if (port == 0 || port > 65535) {
        setError(error, "the invite's port is out of range");
        return std::nullopt;
    }
    invite.port = static_cast<std::uint16_t>(port);
    return invite;
}

std::string newInviteSecret() { return base64url(randomBytes(32)); }

std::string inviteSecretDigest(const std::string& secret)
{
    const auto raw = fromBase64url(secret);
    return raw ? base64url(blake3(*raw)) : std::string();
}

} // namespace logos::peering
