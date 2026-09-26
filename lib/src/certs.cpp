#include "logos/peering/certs.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

#include <stdexcept>

namespace logos::peering {
namespace {

constexpr const char* kRoleArc = "2.25.34192583989300314293127179601651977670.1";
constexpr const char* kCommonName = "logos-runtime";
constexpr long kBackdateSeconds = 3600;

[[noreturn]] void fail(const std::string& what)
{
    ERR_clear_error();
    throw std::runtime_error("certificate: " + what);
}

struct StoreDeleter {
    void operator()(X509_STORE* store) const { X509_STORE_free(store); }
};
struct StoreCtxDeleter {
    void operator()(X509_STORE_CTX* ctx) const { X509_STORE_CTX_free(ctx); }
};

void setSerial(X509* cert)
{
    Bytes raw = randomBytes(16);
    raw[0] = static_cast<std::uint8_t>((raw[0] & 0x3Fu) | 0x40u); // positive, full length
    BIGNUM* number = BN_bin2bn(raw.data(), static_cast<int>(raw.size()), nullptr);
    ASN1_INTEGER* serial = number ? BN_to_ASN1_INTEGER(number, nullptr) : nullptr;
    const bool ok = serial && X509_set_serialNumber(cert, serial) == 1;
    ASN1_INTEGER_free(serial);
    BN_free(number);
    if (!ok) fail("serial number");
}

void setGenericName(X509_NAME* name)
{
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(kCommonName), -1, -1, 0)
        != 1)
        fail("subject name");
}

void setValidity(X509* cert, std::chrono::seconds validity)
{
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -kBackdateSeconds)
        || !X509_gmtime_adj(X509_getm_notAfter(cert), static_cast<long>(validity.count())))
        fail("validity");
}

void addExtension(X509* cert, X509* issuer, int nid, const std::string& value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
    const bool ok = ext && X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    if (!ok) fail(std::string("extension ") + OBJ_nid2sn(nid));
}

// Built directly: the string form of certificatePolicies needs a config database.
void addRolePolicy(X509* cert, Role role)
{
    CERTIFICATEPOLICIES* policies = sk_POLICYINFO_new_null();
    POLICYINFO* info = POLICYINFO_new();
    bool ok = policies && info;
    if (ok) {
        ASN1_OBJECT_free(info->policyid);
        info->policyid = OBJ_txt2obj(roleOid(role).c_str(), 1);
        ok = info->policyid && sk_POLICYINFO_push(policies, info) > 0;
    }
    if (ok) info = nullptr; // owned by the stack now
    ok = ok && X509_add1_ext_i2d(cert, NID_certificate_policies, policies, 0, X509V3_ADD_DEFAULT) == 1;
    POLICYINFO_free(info);
    CERTIFICATEPOLICIES_free(policies);
    if (!ok) fail("extension certificatePolicies");
}

const char* ekuFor(Role role)
{
    switch (role) {
    case Role::Control: return "serverAuth,clientAuth";
    case Role::Provider: return "serverAuth";
    case Role::Client: return "clientAuth";
    }
    return "";
}

bool ekuMatches(X509* leaf, Role role)
{
    const std::uint32_t usage = X509_get_extended_key_usage(leaf);
    const bool server = (usage & XKU_SSL_SERVER) != 0;
    const bool client = (usage & XKU_SSL_CLIENT) != 0;
    switch (role) {
    case Role::Control: return server && client;
    case Role::Provider: return server && !client;
    case Role::Client: return client && !server;
    }
    return false;
}

std::string verifyPurpose(X509* leaf, X509* anchor, int purpose)
{
    std::unique_ptr<X509_STORE, StoreDeleter> store(X509_STORE_new());
    std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter> ctx(X509_STORE_CTX_new());
    if (!store || !ctx || X509_STORE_add_cert(store.get(), anchor) != 1
        || X509_STORE_CTX_init(ctx.get(), store.get(), leaf, nullptr) != 1)
        fail("verification context");
    X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_X509_STRICT);
    X509_STORE_CTX_set_purpose(ctx.get(), purpose);
    const int ok = X509_verify_cert(ctx.get());
    std::string reason;
    if (ok != 1) reason = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()));
    ERR_clear_error();
    return reason;
}

} // namespace

const char* roleName(Role role)
{
    switch (role) {
    case Role::Control: return "control";
    case Role::Provider: return "provider";
    case Role::Client: return "client";
    }
    return "";
}

std::optional<Role> roleFromName(const std::string& name)
{
    for (const Role role : {Role::Control, Role::Provider, Role::Client})
        if (name == roleName(role)) return role;
    return std::nullopt;
}

std::string roleOid(Role role)
{
    switch (role) {
    case Role::Control: return std::string(kRoleArc) + ".1";
    case Role::Provider: return std::string(kRoleArc) + ".2";
    case Role::Client: return std::string(kRoleArc) + ".3";
    }
    return {};
}

Cert makeRootCertificate(EVP_PKEY* rootKey, std::chrono::seconds validity)
{
    if (!isP256(rootKey)) fail("the root key is not P-256");
    Cert cert(X509_new());
    if (!cert || X509_set_version(cert.get(), 2) != 1) fail("allocation");
    setSerial(cert.get());
    setGenericName(X509_get_subject_name(cert.get()));
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get())) != 1) fail("issuer");
    setValidity(cert.get(), validity);
    if (X509_set_pubkey(cert.get(), rootKey) != 1) fail("public key");
    addExtension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    addExtension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    addExtension(cert.get(), cert.get(), NID_subject_key_identifier, "hash");
    addExtension(cert.get(), cert.get(), NID_authority_key_identifier, "keyid:always");
    if (X509_sign(cert.get(), rootKey, EVP_sha256()) <= 0) fail("signature");
    return cert;
}

Cert issueLeaf(EVP_PKEY* rootKey, X509* rootCert, Role role, const Bytes& subjectSpki,
               std::chrono::seconds validity)
{
    PKey subject = publicKeyFromSpki(subjectSpki);
    if (!subject || !isP256(subject.get())) fail("the subject key is not P-256");
    Cert cert(X509_new());
    if (!cert || X509_set_version(cert.get(), 2) != 1) fail("allocation");
    setSerial(cert.get());
    setGenericName(X509_get_subject_name(cert.get()));
    if (X509_set_issuer_name(cert.get(), X509_get_subject_name(rootCert)) != 1) fail("issuer");
    setValidity(cert.get(), validity);
    if (X509_set_pubkey(cert.get(), subject.get()) != 1) fail("public key");
    addExtension(cert.get(), rootCert, NID_basic_constraints, "critical,CA:FALSE");
    addExtension(cert.get(), rootCert, NID_key_usage, "critical,digitalSignature");
    addExtension(cert.get(), rootCert, NID_ext_key_usage, ekuFor(role));
    addRolePolicy(cert.get(), role);
    addExtension(cert.get(), rootCert, NID_subject_key_identifier, "hash");
    addExtension(cert.get(), rootCert, NID_authority_key_identifier, "keyid:always");
    if (X509_sign(cert.get(), rootKey, EVP_sha256()) <= 0) fail("signature");
    return cert;
}

std::optional<Role> leafRole(X509* leaf)
{
    if (!leaf || (X509_get_extension_flags(leaf) & EXFLAG_CA) != 0) return std::nullopt;
    int critical = 0;
    auto* policies = static_cast<CERTIFICATEPOLICIES*>(
        X509_get_ext_d2i(leaf, NID_certificate_policies, &critical, nullptr));
    if (!policies) {
        ERR_clear_error();
        return std::nullopt;
    }
    std::optional<Role> found;
    bool ambiguous = false;
    for (int i = 0; i < sk_POLICYINFO_num(policies); ++i) {
        char oid[160] = {0};
        OBJ_obj2txt(oid, sizeof oid, sk_POLICYINFO_value(policies, i)->policyid, 1);
        for (const Role role : {Role::Control, Role::Provider, Role::Client}) {
            if (roleOid(role) != oid) continue;
            ambiguous = ambiguous || found.has_value();
            found = role;
        }
    }
    CERTIFICATEPOLICIES_free(policies);
    if (ambiguous || !found || !ekuMatches(leaf, *found)) return std::nullopt;
    return found;
}

std::string verifyLeaf(X509* leaf, X509* anchor, Role role)
{
    if (!leaf || !anchor) return "missing certificate";
    const std::optional<Role> marked = leafRole(leaf);
    if (!marked || *marked != role)
        return std::string("the leaf is not marked for the ") + roleName(role) + " role";
    if (role != Role::Client) {
        const std::string reason = verifyPurpose(leaf, anchor, X509_PURPOSE_SSL_SERVER);
        if (!reason.empty()) return reason;
    }
    if (role != Role::Provider) return verifyPurpose(leaf, anchor, X509_PURPOSE_SSL_CLIENT);
    return {};
}

} // namespace logos::peering
