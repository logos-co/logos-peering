#pragma once

#include <string>

namespace logos::peering {

// Module names as the runtime accepts them: a letter, then letters, digits or '_'.
bool isValidModuleName(const std::string& name);

// Method names: a letter or '_', then letters, digits or '_'.
bool isValidMethodName(const std::string& name);

// Local labels for peers: lowercase letter or digit first, then [a-z0-9_-], 1-63 chars.
bool isValidAlias(const std::string& alias);

// Peer-supplied display text: printable, no control characters, at most 64 characters.
bool isValidDisplayName(const std::string& name);

} // namespace logos::peering
