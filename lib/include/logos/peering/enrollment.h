#pragma once

// Enrolled peers, in the spec's shape plus local fields (alias, role).

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

struct Enrollment {
    std::string runtimeInstanceId;
    std::string profile = "logos.remote.tls-tcp";
    std::uint64_t revision = 1;
    std::string status = "active";              // active | suspended | revoked
    std::string trustAnchorPem;                 // the peer's root certificate
    std::vector<std::string> subjectPublicKeys; // pins of its control keys (1 or 2)
    std::string alias;                          // local label
    std::string role = "peer";                  // what the peer may do here: peer | operator
    std::string grantedRole = "peer";           // what this runtime may do there
    std::string displayName;                    // what the peer called itself
    std::vector<std::string> addresses;         // where its control endpoint was reached
    std::uint16_t controlPort = 0;              // 0: it serves none we know of

    std::string anchorPin() const;
    nlohmann::json toJson() const;
    static std::optional<Enrollment> fromJson(const nlohmann::json& value,
                                              std::string* error = nullptr);
};

class EnrollmentStore {
public:
    explicit EnrollmentStore(std::filesystem::path file);

    bool load(std::string* error = nullptr);
    bool save(std::string* error = nullptr) const;

    // Refuses a UUID or root already enrolled, and an alias in use.
    bool add(const Enrollment& enrollment, std::string* error = nullptr);
    // Replaces the enrollment with the same UUID; the revision must grow.
    bool update(const Enrollment& enrollment, std::string* error = nullptr);
    bool remove(const std::string& runtimeInstanceId);

    std::optional<Enrollment> find(const std::string& runtimeInstanceId) const;
    std::optional<Enrollment> findByAlias(const std::string& alias) const;
    std::optional<Enrollment> findByAnchorPin(const std::string& pin) const;
    std::vector<Enrollment> all() const;

private:
    std::filesystem::path file_;
    std::vector<Enrollment> entries_;
};

} // namespace logos::peering
