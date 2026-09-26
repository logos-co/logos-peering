#include "logos/peering/identity.h"

#include "logos/peering/certs.h"
#include "logos/peering/fs.h"

#include <nlohmann/json.hpp>

#include <chrono>

namespace logos::peering {
namespace {

constexpr std::chrono::hours kRootValidity{24 * 365 * 20};

void setError(std::string* error, const std::string& text)
{
    if (error) *error = text;
}

std::string base32(const Bytes& data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (const std::uint8_t byte : data) {
        acc = ((acc << 8) | byte) & 0xFFFFu;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(alphabet[(acc >> bits) & 31u]);
        }
    }
    if (bits > 0) out.push_back(alphabet[(acc << (5 - bits)) & 31u]);
    return out;
}

} // namespace

std::string newUuidV4()
{
    Bytes raw = randomBytes(16);
    raw[6] = static_cast<std::uint8_t>((raw[6] & 0x0Fu) | 0x40u);
    raw[8] = static_cast<std::uint8_t>((raw[8] & 0x3Fu) | 0x80u);
    const std::string digits = hex(raw);
    return digits.substr(0, 8) + "-" + digits.substr(8, 4) + "-" + digits.substr(12, 4) + "-"
           + digits.substr(16, 4) + "-" + digits.substr(20, 12);
}

bool isUuid(const std::string& text)
{
    if (text.size() != 36) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string displayIdFor(const Bytes& rootSpki)
{
    const std::string encoded = base32(sha256(rootSpki)).substr(0, 20);
    return encoded.substr(0, 5) + "-" + encoded.substr(5, 5) + "-" + encoded.substr(10, 5) + "-"
           + encoded.substr(15, 5);
}

Bytes RuntimeIdentity::rootSpki() const { return spkiDer(rootCert.get()); }

std::string RuntimeIdentity::rootPin() const { return spkiPin(rootSpki()); }

std::string RuntimeIdentity::displayId() const { return displayIdFor(rootSpki()); }

std::optional<RuntimeIdentity> loadOrCreateIdentity(const std::filesystem::path& dir,
                                                    std::string* error)
{
    if (!ensurePrivateDir(dir, error)) return std::nullopt;
    const auto idPath = dir / "identity.json";
    const auto keyPath = dir / "root.key.pem";
    const auto certPath = dir / "root.cert.pem";

    const auto idText = readFile(idPath);
    const auto keyText = readFile(keyPath);
    const auto certText = readFile(certPath);
    if (idText || keyText || certText) {
        if (!idText || !keyText || !certText) {
            setError(error, "the identity in " + dir.string() + " is incomplete");
            return std::nullopt;
        }
        const auto doc = nlohmann::json::parse(*idText, nullptr, false);
        RuntimeIdentity identity;
        if (doc.is_object() && doc.contains("uuid") && doc["uuid"].is_string())
            identity.uuid = doc["uuid"].get<std::string>();
        identity.rootKey = privateKeyFromPem(*keyText);
        identity.rootCert = certFromPem(*certText);
        if (!isUuid(identity.uuid) || !identity.rootKey || !identity.rootCert
            || !isP256(identity.rootKey.get())
            || X509_check_private_key(identity.rootCert.get(), identity.rootKey.get()) != 1) {
            setError(error, "the identity in " + dir.string() + " is damaged");
            return std::nullopt;
        }
        return identity;
    }

    RuntimeIdentity identity;
    identity.uuid = newUuidV4();
    identity.rootKey = generateP256();
    identity.rootCert = makeRootCertificate(identity.rootKey.get(), kRootValidity);
    const nlohmann::json doc = {{"uuid", identity.uuid}, {"profile", "logos.remote.tls-tcp"}};
    if (!writeFileAtomically(keyPath, privateKeyPem(identity.rootKey.get()), error)
        || !writeFileAtomically(certPath, certPem(identity.rootCert.get()), error)
        || !writeFileAtomically(idPath, doc.dump(2) + "\n", error))
        return std::nullopt;
    return identity;
}

} // namespace logos::peering
