#include "logos/peering/config.h"

#include "logos/peering/callers.h"
#include "logos/peering/identity.h"
#include "logos/peering/names.h"

#include <algorithm>
#include <cctype>
#include <set>

namespace logos::peering {
namespace {

using json = nlohmann::json;

bool fail(std::string* error, const std::string& text)
{
    if (error) *error = text;
    return false;
}

bool onlyKeys(const json& value, std::initializer_list<const char*> keys, const std::string& where,
              std::string* error)
{
    if (!value.is_object()) return fail(error, where + " is not an object");
    const std::set<std::string> allowed(keys.begin(), keys.end());
    for (const auto& item : value.items())
        if (!allowed.count(item.key())) return fail(error, "unknown key " + where + "." + item.key());
    return true;
}

bool readBool(const json& value, const char* key, bool& out, std::string* error)
{
    const auto it = value.find(key);
    if (it == value.end()) return true;
    if (!it->is_boolean()) return fail(error, std::string(key) + " is not a boolean");
    out = it->get<bool>();
    return true;
}

bool readString(const json& value, const char* key, std::string& out, std::string* error)
{
    const auto it = value.find(key);
    if (it == value.end()) return true;
    if (!it->is_string()) return fail(error, std::string(key) + " is not a string");
    out = it->get<std::string>();
    return true;
}

bool readPort(const json& value, const char* key, std::uint16_t& out, std::string* error)
{
    const auto it = value.find(key);
    if (it == value.end()) return true;
    if (!it->is_number_integer() || it->get<std::int64_t>() < 0 || it->get<std::int64_t>() > 65535)
        return fail(error, std::string(key) + " is not a port");
    out = static_cast<std::uint16_t>(it->get<std::int64_t>());
    return true;
}

// "7450-7499", "7450" or 7450.
bool readPortRange(const json& value, std::uint16_t& low, std::uint16_t& high, std::string* error)
{
    const auto it = value.find("ports");
    if (it == value.end()) return true;
    auto parse = [](const std::string& text, std::uint16_t& out) {
        if (text.empty() || text.size() > 5
            || !std::all_of(text.begin(), text.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); }))
            return false;
        const long n = std::stol(text);
        if (n < 1 || n > 65535) return false;
        out = static_cast<std::uint16_t>(n);
        return true;
    };
    if (it->is_number_integer()) {
        const auto n = it->get<std::int64_t>();
        if (n < 1 || n > 65535) return fail(error, "exports.ports is not a port");
        low = high = static_cast<std::uint16_t>(n);
        return true;
    }
    if (!it->is_string()) return fail(error, "exports.ports is not a port range");
    const std::string text = it->get<std::string>();
    const auto dash = text.find('-');
    if (dash == std::string::npos ? !parse(text, low) || !parse(text, high)
                                  : !parse(text.substr(0, dash), low) || !parse(text.substr(dash + 1), high)
        || low > high)
        return fail(error, "exports.ports is not a port range");
    return true;
}

bool isHost(const std::string& host)
{
    if (host.empty() || host.size() > 253) return false;
    return std::all_of(host.begin(), host.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == ':';
    });
}

} // namespace

bool isReservedName(const std::string& name)
{
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    static const std::set<std::string> reserved = {
        "core", "core_service", "capability_module", "modules_state", "peering_identity",
        "peering_module", "peering_control", "package_ops", "runtime"};
    return reserved.count(lower) || lower.rfind("logos_", 0) == 0 || lower.rfind("peering_", 0) == 0;
}

std::optional<ExportRule> parseExportRule(const json& value, std::string* error)
{
    ExportRule rule;
    if (value.is_null()) return rule;
    if (!onlyKeys(value, {"events"}, "export", error) || !readBool(value, "events", rule.events, error))
        return std::nullopt;
    return rule;
}

std::optional<ImportRule> parseImportRule(const std::string& name, const json& value,
                                          std::string* error)
{
    ImportRule rule;
    if (!onlyKeys(value, {"from", "module", "prefer", "version", "allowed_callers", "events"},
                  "imports." + name, error)
        || !readString(value, "from", rule.from, error) || !readString(value, "module", rule.module, error)
        || !readString(value, "prefer", rule.prefer, error)
        || !readString(value, "version", rule.version, error)
        || !readBool(value, "events", rule.events, error))
        return std::nullopt;
    if (rule.module.empty()) rule.module = name;
    if (!isValidModuleName(name) || isReservedName(name)) {
        fail(error, "an import cannot be called " + name);
        return std::nullopt;
    }
    if (!isUuid(rule.from)) {
        fail(error, "imports." + name + ".from is not a runtime id");
        return std::nullopt;
    }
    if (!isValidModuleName(rule.module) || isReservedName(rule.module)) {
        fail(error, "imports." + name + ".module cannot be imported");
        return std::nullopt;
    }
    if (rule.prefer != "remote" && rule.prefer != "local") {
        fail(error, "imports." + name + ".prefer is remote or local");
        return std::nullopt;
    }
    if (const auto it = value.find("allowed_callers"); it != value.end()) {
        if (!it->is_array()) {
            fail(error, "imports." + name + ".allowed_callers is not a list");
            return std::nullopt;
        }
        for (const auto& caller : *it) {
            if (!caller.is_string() || !isValidConsumer(caller.get<std::string>())) {
                fail(error, "imports." + name + ".allowed_callers holds an invalid consumer");
                return std::nullopt;
            }
            rule.allowedCallers.push_back(caller.get<std::string>());
        }
    }
    return rule;
}

std::optional<PeeringConfig> parsePeeringConfig(const json& value, std::string* error)
{
    PeeringConfig config;
    if (value.is_null()) return config;
    if (!onlyKeys(value, {"name", "shell", "control", "exports", "operator", "announce", "browse", "imports"},
                  "peering", error)
        || !readString(value, "name", config.name, error) || !readString(value, "shell", config.shell, error)
        || !readBool(value, "operator", config.operatorRoutes, error)
        || !readBool(value, "announce", config.announce, error)
        || !readBool(value, "browse", config.browse, error))
        return std::nullopt;
    if (!config.name.empty() && !isValidDisplayName(config.name)) {
        fail(error, "peering.name is not printable text of at most 64 characters");
        return std::nullopt;
    }
    if (!config.shell.empty() && !isValidModuleName(config.shell)) {
        fail(error, "peering.shell is not a module name");
        return std::nullopt;
    }
    if (const auto it = value.find("control"); it != value.end()) {
        if (!onlyKeys(*it, {"enabled", "host", "port", "advertise"}, "control", error)
            || !readBool(*it, "enabled", config.control, error)
            || !readString(*it, "host", config.controlHost, error)
            || !readPort(*it, "port", config.controlPort, error)
            || !readString(*it, "advertise", config.advertise, error))
            return std::nullopt;
        if (!isHost(config.controlHost) || (!config.advertise.empty() && !isHost(config.advertise))) {
            fail(error, "control.host and control.advertise are addresses");
            return std::nullopt;
        }
    }
    if (const auto it = value.find("exports"); it != value.end()) {
        if (!onlyKeys(*it, {"enabled", "ports", "modules"}, "exports", error)
            || !readBool(*it, "enabled", config.exports, error)
            || !readPortRange(*it, config.exportPortMin, config.exportPortMax, error))
            return std::nullopt;
        if (const auto modules = it->find("modules"); modules != it->end()) {
            if (!modules->is_object()) {
                fail(error, "exports.modules is not an object");
                return std::nullopt;
            }
            for (const auto& item : modules->items()) {
                if (!isValidModuleName(item.key()) || isReservedName(item.key())) {
                    fail(error, "exports.modules cannot hold " + item.key());
                    return std::nullopt;
                }
                auto rule = parseExportRule(item.value(), error);
                if (!rule) return std::nullopt;
                config.exportModules[item.key()] = *rule;
            }
        }
    }
    if (config.exports && !config.control) {
        fail(error, "exports need the control endpoint");
        return std::nullopt;
    }
    if (config.announce && !config.control) {
        fail(error, "announcing needs the control endpoint");
        return std::nullopt;
    }
    if (const auto it = value.find("imports"); it != value.end()) {
        if (!it->is_object()) {
            fail(error, "imports is not an object");
            return std::nullopt;
        }
        for (const auto& item : it->items()) {
            auto rule = parseImportRule(item.key(), item.value(), error);
            if (!rule) return std::nullopt;
            if (config.exportModules.count(item.key())) {
                fail(error, item.key() + " cannot be both imported and exported");
                return std::nullopt;
            }
            config.imports[item.key()] = *rule;
        }
    }
    return config;
}

json toJson(const ImportRule& rule)
{
    return {{"from", rule.from},
            {"module", rule.module},
            {"prefer", rule.prefer},
            {"version", rule.version},
            {"allowed_callers", rule.allowedCallers},
            {"events", rule.events}};
}

json toJson(const ExportRule& rule) { return {{"events", rule.events}}; }

} // namespace logos::peering
