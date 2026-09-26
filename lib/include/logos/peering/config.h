#pragma once

// The peering configuration a runtime passes to peering_module (its
// peering_config), parsed strictly: an unknown key is an error.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace logos::peering {

struct ExportRule {
    bool events = false; // share its events with importers
};

struct ImportRule {
    std::string from;                        // the providing runtime's UUID
    std::string module;                      // its module name there
    std::string prefer = "remote";           // remote | local, when a local copy exists
    std::string version;                     // informational in v1
    std::vector<std::string> allowedCallers; // local consumers it admits ("*": any)
    bool events = false;
};

struct PeeringConfig {
    std::string name;  // shown to others while pairing
    std::string shell; // the shell that may manage peering
    bool control = false;
    std::string controlHost = "0.0.0.0";
    std::uint16_t controlPort = 7443;
    std::string advertise; // the address invites carry; empty: the control host
    // A single-use invite kept in a 0600 file for a same-user app on this
    // machine, redeemable over loopback only and replaced once used.
    bool localInvite = false;
    std::string localInvitePath; // empty: <state>/local-invite
    std::string localInviteRole = "peer";
    // What a runtime paired through it may call ("*": every export).
    std::vector<std::string> localInviteAllow;
    bool exports = false;
    std::uint16_t exportPortMin = 0;
    std::uint16_t exportPortMax = 0;
    std::map<std::string, ExportRule> exportModules;
    bool operatorRoutes = false;
    bool announce = false;
    bool browse = false;
    std::map<std::string, ImportRule> imports;
};

std::optional<PeeringConfig> parsePeeringConfig(const nlohmann::json& value,
                                                std::string* error = nullptr);

// `name` is the import's local name; `module` defaults to it.
std::optional<ImportRule> parseImportRule(const std::string& name, const nlohmann::json& value,
                                          std::string* error = nullptr);
std::optional<ExportRule> parseExportRule(const nlohmann::json& value, std::string* error = nullptr);
nlohmann::json toJson(const ImportRule& rule);
nlohmann::json toJson(const ExportRule& rule);

// Names peering never imports or exports: the runtime's own and peering's.
bool isReservedName(const std::string& name);
// A module a remote policy may name, or "*" for every export.
bool isPolicyTarget(const std::string& target);

} // namespace logos::peering
