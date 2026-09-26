#include "logos/peering/invite_store.h"

#include "logos/peering/crypto.h"
#include "logos/peering/fs.h"

#include <algorithm>

namespace logos::peering {
namespace {

using SysClock = std::chrono::system_clock;

std::int64_t toSeconds(SysClock::time_point t)
{
    return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

} // namespace

InviteStore::InviteStore(std::filesystem::path file, Now now)
    : file_(std::move(file)), now_(now ? std::move(now) : Now([] { return SysClock::now(); }))
{
}

bool InviteStore::load(std::string* error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    invites_.clear();
    if (file_.empty()) return true;
    const auto text = readFile(file_);
    if (!text) return true;
    const auto doc = nlohmann::json::parse(*text, nullptr, false);
    if (!doc.is_object() || !doc.contains("invites") || !doc["invites"].is_array()) {
        if (error) *error = file_.string() + " is not an invite file";
        return false;
    }
    for (const auto& item : doc["invites"]) {
        if (!item.is_object() || !item.contains("digest") || !item.contains("role")
            || !item.contains("expires") || !item["digest"].is_string() || !item["role"].is_string()
            || !item["expires"].is_number_integer())
            continue;
        IssuedInvite invite;
        invite.secretDigest = item["digest"].get<std::string>();
        invite.role = item["role"].get<std::string>();
        invite.expires = SysClock::time_point(std::chrono::seconds(item["expires"].get<std::int64_t>()));
        invite.issuedBy = item.value("issued_by", "");
        invites_.push_back(invite);
    }
    purgeLocked();
    return true;
}

std::string InviteStore::issue(const std::string& role, std::chrono::seconds ttl,
                               const std::string& issuedBy)
{
    const std::chrono::seconds cap =
        role == "operator" ? std::chrono::seconds(kOperatorTtl) : std::chrono::seconds(kPeerTtl);
    const std::chrono::seconds effective = ttl.count() <= 0 ? cap : std::min(ttl, cap);
    const std::string secret = newInviteSecret();
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked();
    invites_.push_back({inviteSecretDigest(secret), role == "operator" ? "operator" : "peer",
                        now_() + effective, issuedBy});
    saveLocked();
    return secret;
}

std::optional<IssuedInvite> InviteStore::redeem(const std::string& secret,
                                                const std::function<bool(const IssuedInvite&)>& accept)
{
    const std::string digest = inviteSecretDigest(secret);
    if (digest.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked();
    const auto raw = fromBase64url(digest);
    for (auto it = invites_.begin(); it != invites_.end(); ++it) {
        const auto stored = fromBase64url(it->secretDigest);
        if (!raw || !stored || !constantTimeEqual(*raw, *stored)) continue;
        if (accept && !accept(*it)) return std::nullopt;
        IssuedInvite found = *it;
        invites_.erase(it);
        saveLocked();
        return found;
    }
    return std::nullopt;
}

bool InviteStore::revoke(const std::string& secretDigest)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto before = invites_.size();
    invites_.erase(std::remove_if(invites_.begin(), invites_.end(),
                                  [&](const IssuedInvite& i) { return i.secretDigest == secretDigest; }),
                   invites_.end());
    if (invites_.size() == before) return false;
    saveLocked();
    return true;
}

bool InviteStore::anyLive()
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked();
    return !invites_.empty();
}

std::vector<IssuedInvite> InviteStore::live()
{
    std::lock_guard<std::mutex> lock(mutex_);
    purgeLocked();
    return invites_;
}

void InviteStore::purgeLocked()
{
    const auto now = now_();
    const auto before = invites_.size();
    invites_.erase(std::remove_if(invites_.begin(), invites_.end(),
                                  [&](const IssuedInvite& i) { return i.expires <= now; }),
                   invites_.end());
    if (invites_.size() != before) saveLocked();
}

void InviteStore::saveLocked()
{
    if (file_.empty()) return;
    nlohmann::json list = nlohmann::json::array();
    for (const auto& i : invites_)
        list.push_back({{"digest", i.secretDigest},
                        {"role", i.role},
                        {"expires", toSeconds(i.expires)},
                        {"issued_by", i.issuedBy}});
    writeFileAtomically(file_, nlohmann::json{{"version", 1}, {"invites", list}}.dump(2) + "\n");
}

} // namespace logos::peering
