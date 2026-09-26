#include "logos/peering/crypto.h"

#include <blake3.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cstring>
#include <stdexcept>

namespace logos::peering {
namespace {

struct BioDeleter {
    void operator()(BIO* bio) const { BIO_free(bio); }
};
using Bio = std::unique_ptr<BIO, BioDeleter>;

struct ReqDeleter {
    void operator()(X509_REQ* req) const { X509_REQ_free(req); }
};

[[noreturn]] void fail(const char* what)
{
    const unsigned long code = ERR_get_error();
    char text[256] = {0};
    if (code) ERR_error_string_n(code, text, sizeof text);
    ERR_clear_error();
    throw std::runtime_error(code ? std::string(what) + ": " + text : std::string(what));
}

Bio memoryBio() { return Bio(BIO_new(BIO_s_mem())); }

Bio readBio(const std::string& text)
{
    return Bio(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())));
}

std::string drain(BIO* bio)
{
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string();
}

template <typename Encode>
Bytes encodeDer(Encode encode)
{
    const int size = encode(nullptr);
    if (size <= 0) fail("DER encoding");
    Bytes out(static_cast<std::size_t>(size));
    unsigned char* cursor = out.data();
    encode(&cursor);
    return out;
}

} // namespace

Bytes toBytes(const std::string& text) { return Bytes(text.begin(), text.end()); }

std::string toString(const Bytes& data) { return std::string(data.begin(), data.end()); }

Bytes randomBytes(std::size_t count)
{
    Bytes out(count);
    if (count && RAND_bytes(out.data(), static_cast<int>(count)) != 1) fail("RAND_bytes");
    return out;
}

std::string base64url(const Bytes& data)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const std::uint8_t byte : data) {
        acc = ((acc << 8) | byte) & 0xFFFFFFu;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(alphabet[(acc >> bits) & 63u]);
        }
    }
    if (bits > 0) out.push_back(alphabet[(acc << (6 - bits)) & 63u]);
    return out;
}

std::optional<Bytes> fromBase64url(const std::string& text)
{
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    if (text.size() % 4 == 1) return std::nullopt;
    Bytes out;
    out.reserve(text.size() * 3 / 4);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : text) {
        const int v = value(c);
        if (v < 0) return std::nullopt;
        acc = ((acc << 6) | static_cast<std::uint32_t>(v)) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xFFu));
        }
    }
    // Leftover bits must be zero, so each value has exactly one encoding.
    if (bits > 0 && (acc & ((1u << bits) - 1u)) != 0) return std::nullopt;
    return out;
}

std::string hex(const Bytes& data)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (const std::uint8_t byte : data) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    return out;
}

Bytes sha256(const Bytes& data)
{
    Bytes out(32);
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &size, EVP_sha256(), nullptr) != 1)
        fail("SHA-256");
    return out;
}

Bytes blake3(const Bytes& data)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    Bytes out(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    return out;
}

Bytes hmacSha256(const Bytes& key, const Bytes& data)
{
    Bytes out(32);
    unsigned int size = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              out.data(), &size))
        fail("HMAC-SHA-256");
    return out;
}

bool constantTimeEqual(const Bytes& a, const Bytes& b)
{
    return a.size() == b.size() && (a.empty() || CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0);
}

void appendFramed(Bytes& out, const Bytes& part)
{
    const auto size = static_cast<std::uint32_t>(part.size());
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((size >> shift) & 0xFFu));
    out.insert(out.end(), part.begin(), part.end());
}

void appendBe64(Bytes& out, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
}

bool isP256(EVP_PKEY* key)
{
    if (!key || !EVP_PKEY_is_a(key, "EC")) return false;
    char group[64] = {0};
    std::size_t length = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group,
                                       &length) != 1)
        return false;
    return std::strcmp(group, "prime256v1") == 0 || std::strcmp(group, "P-256") == 0;
}

PKey generateP256()
{
    PKey key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    if (!key) fail("P-256 key generation");
    return key;
}

std::string privateKeyPem(EVP_PKEY* key)
{
    Bio bio = memoryBio();
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        fail("private key PEM");
    return drain(bio.get());
}

PKey privateKeyFromPem(const std::string& pem)
{
    Bio bio = readBio(pem);
    PKey key(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    ERR_clear_error();
    return key;
}

Bytes spkiDer(EVP_PKEY* key)
{
    return encodeDer([key](unsigned char** out) { return i2d_PUBKEY(key, out); });
}

Bytes spkiDer(X509* cert)
{
    X509_PUBKEY* pub = X509_get_X509_PUBKEY(cert);
    return encodeDer([pub](unsigned char** out) { return i2d_X509_PUBKEY(pub, out); });
}

PKey publicKeyFromSpki(const Bytes& der)
{
    const unsigned char* cursor = der.data();
    PKey key(d2i_PUBKEY(nullptr, &cursor, static_cast<long>(der.size())));
    ERR_clear_error();
    if (!key || cursor != der.data() + der.size()) return PKey();
    return key;
}

std::string spkiPin(const Bytes& spki) { return "sha256:" + base64url(sha256(spki)); }

std::string certPem(X509* cert)
{
    Bio bio = memoryBio();
    if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) fail("certificate PEM");
    return drain(bio.get());
}

Cert certFromPem(const std::string& pem)
{
    Bio bio = readBio(pem);
    Cert cert(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    ERR_clear_error();
    return cert;
}

std::vector<Cert> certsFromPem(const std::string& pem)
{
    std::vector<Cert> out;
    Bio bio = readBio(pem);
    while (bio) {
        X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!cert) break;
        out.emplace_back(cert);
    }
    ERR_clear_error();
    return out;
}

Bytes certDer(X509* cert)
{
    return encodeDer([cert](unsigned char** out) { return i2d_X509(cert, out); });
}

Cert certFromDer(const Bytes& der)
{
    const unsigned char* cursor = der.data();
    Cert cert(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
    ERR_clear_error();
    if (!cert || cursor != der.data() + der.size()) return Cert();
    return cert;
}

std::string makeCsrPem(EVP_PKEY* key)
{
    std::unique_ptr<X509_REQ, ReqDeleter> req(X509_REQ_new());
    if (!req || X509_REQ_set_version(req.get(), 0) != 1 || X509_REQ_set_pubkey(req.get(), key) != 1
        || X509_REQ_sign(req.get(), key, EVP_sha256()) <= 0)
        fail("CSR");
    Bio bio = memoryBio();
    if (!bio || PEM_write_bio_X509_REQ(bio.get(), req.get()) != 1) fail("CSR PEM");
    return drain(bio.get());
}

std::optional<Bytes> spkiFromCsrPem(const std::string& csrPem)
{
    Bio bio = readBio(csrPem);
    std::unique_ptr<X509_REQ, ReqDeleter> req(
        bio ? PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    EVP_PKEY* key = req ? X509_REQ_get0_pubkey(req.get()) : nullptr;
    const bool valid = key && isP256(key) && X509_REQ_verify(req.get(), key) == 1;
    ERR_clear_error();
    if (!valid) return std::nullopt;
    return spkiDer(key);
}

} // namespace logos::peering
