#pragma once

// Runtime root certificates and role-marked leaves. Certificates carry no names
// (privacy): a leaf says only which role it may play, and peers pin exact keys.

#include "logos/peering/crypto.h"

#include <chrono>
#include <optional>
#include <string>

namespace logos::peering {

enum class Role { Control, Provider, Client };

const char* roleName(Role role);
std::optional<Role> roleFromName(const std::string& name);
// Certificate-policy OID under the UUID arc 2.25.34192583989300314293127179601651977670.
std::string roleOid(Role role);

// Self-signed v3 CA, pathlen 0, backdated an hour for clock skew.
Cert makeRootCertificate(EVP_PKEY* rootKey, std::chrono::seconds validity);

// A CA:FALSE leaf for `subjectSpki`, marked with the role's EKU and policy OID.
Cert issueLeaf(EVP_PKEY* rootKey, X509* rootCert, Role role, const Bytes& subjectSpki,
               std::chrono::seconds validity);

// The single role a leaf is marked with, or nothing when absent or ambiguous.
std::optional<Role> leafRole(X509* leaf);

// Empty when `leaf` chains to `anchor` and carries `role`; otherwise the reason.
std::string verifyLeaf(X509* leaf, X509* anchor, Role role);

} // namespace logos::peering
