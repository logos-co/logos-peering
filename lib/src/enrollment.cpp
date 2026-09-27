#include "logos/peering/enrollment.h"

#include "logos/peering/crypto.h"
#include "logos/peering/fs.h"
#include "logos/peering/identity.h"
#include "logos/peering/names.h"

#include <algorithm>

namespace logos::peering {
namespace {

void setError(std::string* error, const std::string& text)
{
    if (error) *error = text;
}

bool isPin(const std::string& pin)
{
    if (pin.rfind("sha256:", 0) != 0) return false;
    const auto raw = fromBase64url(pin.substr(7));
    return raw && raw->size() == 32;
}

template <typename T>
bool readField(const nlohmann::json& value, const char* key, T& out)
{
    const auto it = value.find(key);
    if (it == value.end()) return false;
    try {
        out = it->get<T>();
        return true;
    } catch (const nlohmann::json::exception&) {
        return false;
    }
}

bool hasUse(const std::vector<std::string>& uses, const char* use)
{
    return std::find(uses.begin(), uses.end(), use) != uses.end();
}

// provider-access, and runtime-control at most once besides it.
bool validUses(const std::vector<std::string>& uses)
{
    if (!hasUse(uses, kProviderAccess) || uses.size() > 2) return false;
    return uses.size() == 1 || (uses[0] != uses[1] && hasUse(uses, kRuntimeControl));
}

} // namespace

std::vector<std::string> usesForRole(const std::string& role)
{
    if (role == kRuntimeControl || role == "operator") return {kProviderAccess, kRuntimeControl};
    return {kProviderAccess};
}

bool Enrollment::runtimeControl() const { return hasUse(uses, kRuntimeControl); }
bool Enrollment::grantedRuntimeControl() const { return hasUse(grantedUses, kRuntimeControl); }

std::string Enrollment::anchorPin() const
{
    const Cert anchor = certFromPem(trustAnchorPem);
    return anchor ? spkiPin(spkiDer(anchor.get())) : std::string();
}

nlohmann::json Enrollment::toJson() const
{
    return {{"runtime_instance_id", runtimeInstanceId},
            {"profile", profile},
            {"revision", revision},
            {"status", status},
            {"trust_anchor", trustAnchorPem},
            {"subject_public_keys", subjectPublicKeys},
            {"alias", alias},
            {"uses", uses},
            {"granted_uses", grantedUses},
            {"display_name", displayName},
            {"addresses", addresses},
            {"control_port", controlPort}};
}

std::optional<Enrollment> Enrollment::fromJson(const nlohmann::json& value, std::string* error)
{
    Enrollment e;
    if (!value.is_object() || !readField(value, "runtime_instance_id", e.runtimeInstanceId)
        || !readField(value, "profile", e.profile) || !readField(value, "revision", e.revision)
        || !readField(value, "status", e.status) || !readField(value, "trust_anchor", e.trustAnchorPem)
        || !readField(value, "subject_public_keys", e.subjectPublicKeys)
        || !readField(value, "alias", e.alias)) {
        setError(error, "an enrollment is missing a field");
        return std::nullopt;
    }
    // Before uses there was a role, "operator" for Runtime Control.
    std::string role;
    if (value.contains("uses")) {
        if (!readField(value, "uses", e.uses)) {
            setError(error, "an enrollment's uses are not a list of names");
            return std::nullopt;
        }
    } else if (readField(value, "role", role)) {
        e.uses = usesForRole(role);
    } else {
        setError(error, "an enrollment is missing a field");
        return std::nullopt;
    }
    if (value.contains("granted_uses")) readField(value, "granted_uses", e.grantedUses);
    else if (readField(value, "granted_role", role)) e.grantedUses = usesForRole(role);
    readField(value, "display_name", e.displayName);
    readField(value, "addresses", e.addresses);
    readField(value, "control_port", e.controlPort);
    const bool keysOk = !e.subjectPublicKeys.empty() && e.subjectPublicKeys.size() <= 2
                        && std::all_of(e.subjectPublicKeys.begin(), e.subjectPublicKeys.end(), isPin);
    if (!isUuid(e.runtimeInstanceId) || e.profile != "logos.remote.tls-tcp" || e.revision == 0
        || (e.status != "active" && e.status != "suspended" && e.status != "revoked") || !keysOk
        || !isValidAlias(e.alias) || !validUses(e.uses) || !validUses(e.grantedUses) || e.addresses.size() > 8
        || (!e.displayName.empty() && !isValidDisplayName(e.displayName))
        || e.anchorPin().empty()) {
        setError(error, "an enrollment is malformed");
        return std::nullopt;
    }
    return e;
}

EnrollmentStore::EnrollmentStore(std::filesystem::path file) : file_(std::move(file)) {}

bool EnrollmentStore::load(std::string* error)
{
    entries_.clear();
    const auto text = readFile(file_);
    if (!text) return true;
    const auto doc = nlohmann::json::parse(*text, nullptr, false);
    if (!doc.is_object() || !doc.contains("peers") || !doc["peers"].is_array()) {
        setError(error, file_.string() + " is not an enrollment file");
        return false;
    }
    for (const auto& item : doc["peers"]) {
        auto e = Enrollment::fromJson(item, error);
        if (!e) return false;
        entries_.push_back(std::move(*e));
    }
    return true;
}

bool EnrollmentStore::save(std::string* error) const
{
    nlohmann::json peers = nlohmann::json::array();
    for (const auto& e : entries_) peers.push_back(e.toJson());
    return writeFileAtomically(file_, nlohmann::json{{"version", 1}, {"peers", peers}}.dump(2) + "\n",
                               error);
}

bool EnrollmentStore::add(const Enrollment& enrollment, std::string* error)
{
    std::string reason;
    if (!Enrollment::fromJson(enrollment.toJson(), &reason)) {
        setError(error, reason);
        return false;
    }
    const std::string pin = enrollment.anchorPin();
    for (const auto& e : entries_) {
        if (e.runtimeInstanceId == enrollment.runtimeInstanceId) {
            setError(error, "runtime " + e.runtimeInstanceId + " is already enrolled");
            return false;
        }
        if (e.anchorPin() == pin) {
            setError(error, "that root is already enrolled as " + e.alias);
            return false;
        }
        if (e.alias == enrollment.alias) {
            setError(error, "the alias " + e.alias + " is in use");
            return false;
        }
    }
    entries_.push_back(enrollment);
    return true;
}

bool EnrollmentStore::update(const Enrollment& enrollment, std::string* error)
{
    std::string reason;
    if (!Enrollment::fromJson(enrollment.toJson(), &reason)) {
        setError(error, reason);
        return false;
    }
    for (auto& e : entries_) {
        if (e.runtimeInstanceId != enrollment.runtimeInstanceId) continue;
        if (enrollment.revision <= e.revision) {
            setError(error, "an update must raise the revision");
            return false;
        }
        for (const auto& other : entries_)
            if (&other != &e && other.alias == enrollment.alias) {
                setError(error, "the alias " + other.alias + " is in use");
                return false;
            }
        e = enrollment;
        return true;
    }
    setError(error, "runtime " + enrollment.runtimeInstanceId + " is not enrolled");
    return false;
}

bool EnrollmentStore::remove(const std::string& runtimeInstanceId)
{
    const auto it = std::remove_if(entries_.begin(), entries_.end(), [&](const Enrollment& e) {
        return e.runtimeInstanceId == runtimeInstanceId;
    });
    const bool removed = it != entries_.end();
    entries_.erase(it, entries_.end());
    return removed;
}

std::optional<Enrollment> EnrollmentStore::find(const std::string& runtimeInstanceId) const
{
    for (const auto& e : entries_)
        if (e.runtimeInstanceId == runtimeInstanceId) return e;
    return std::nullopt;
}

std::optional<Enrollment> EnrollmentStore::findByAlias(const std::string& alias) const
{
    for (const auto& e : entries_)
        if (e.alias == alias) return e;
    return std::nullopt;
}

std::optional<Enrollment> EnrollmentStore::findByAnchorPin(const std::string& pin) const
{
    for (const auto& e : entries_)
        if (e.anchorPin() == pin) return e;
    return std::nullopt;
}

std::vector<Enrollment> EnrollmentStore::all() const { return entries_; }

} // namespace logos::peering
