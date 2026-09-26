#pragma once

// Byte helpers and the OpenSSL/BLAKE3 primitives the rest of libpeering builds on.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace logos::peering {

using Bytes = std::vector<std::uint8_t>;

Bytes toBytes(const std::string& text);
std::string toString(const Bytes& data);

Bytes randomBytes(std::size_t count);
std::string base64url(const Bytes& data);
std::optional<Bytes> fromBase64url(const std::string& text);
std::string hex(const Bytes& data);

Bytes sha256(const Bytes& data);
Bytes blake3(const Bytes& data);
Bytes hmacSha256(const Bytes& key, const Bytes& data);
bool constantTimeEqual(const Bytes& a, const Bytes& b);

// Appends a big-endian 32-bit length, then the bytes: unambiguous concatenation.
void appendFramed(Bytes& out, const Bytes& part);
void appendBe64(Bytes& out, std::uint64_t value);

struct PKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct CertDeleter {
    void operator()(X509* cert) const { X509_free(cert); }
};
using PKey = std::unique_ptr<EVP_PKEY, PKeyDeleter>;
using Cert = std::unique_ptr<X509, CertDeleter>;

PKey generateP256();
// Every key in the scheme is ECDSA P-256.
bool isP256(EVP_PKEY* key);
// PKCS#8 PEM, unencrypted: callers keep it in memory or in a 0600 file.
std::string privateKeyPem(EVP_PKEY* key);
PKey privateKeyFromPem(const std::string& pem);

Bytes spkiDer(EVP_PKEY* key);
Bytes spkiDer(X509* cert);
PKey publicKeyFromSpki(const Bytes& der);
// "sha256:" + base64url(SHA-256(SPKI DER)): how peers pin one exact key.
std::string spkiPin(const Bytes& spki);

std::string certPem(X509* cert);
Cert certFromPem(const std::string& pem);
std::vector<Cert> certsFromPem(const std::string& pem);
Bytes certDer(X509* cert);
Cert certFromDer(const Bytes& der);

// A signed CSR proves possession of its key; returns the SPKI, or nothing.
std::optional<Bytes> spkiFromCsrPem(const std::string& csrPem);
std::string makeCsrPem(EVP_PKEY* key);

} // namespace logos::peering
