#include "logos/peering/audit.h"

#include "logos/peering/fs.h"

#include <chrono>
#include <ctime>

namespace logos::peering {
namespace {

std::string nowRfc3339()
{
    const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char text[32] = {0};
    std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &utc);
    return text;
}

} // namespace

AuditLog::AuditLog(std::filesystem::path file) : file_(std::move(file)) {}

void AuditLog::record(const std::string& event, nlohmann::json fields)
{
    if (!fields.is_object()) fields = nlohmann::json::object();
    fields["ts"] = nowRfc3339();
    fields["event"] = event;
    std::lock_guard<std::mutex> lock(mutex_);
    appendLine(file_, fields.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
}

} // namespace logos::peering
