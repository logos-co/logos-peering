#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace logos::peering {

// Creates `dir` with its parents and restricts it to the owner.
bool ensurePrivateDir(const std::filesystem::path& dir, std::string* error = nullptr);

// Writes a 0600 temporary file beside `path`, syncs it, then renames it over `path`.
bool writeFileAtomically(const std::filesystem::path& path, const std::string& content,
                         std::string* error = nullptr);

std::optional<std::string> readFile(const std::filesystem::path& path);

// Appends one line to a 0600 file, creating it if needed.
bool appendLine(const std::filesystem::path& path, const std::string& line,
                std::string* error = nullptr);

} // namespace logos::peering
