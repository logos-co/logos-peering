#include "logos/peering/names.h"

namespace logos::peering {
namespace {

bool isLower(char c) { return c >= 'a' && c <= 'z'; }
bool isUpper(char c) { return c >= 'A' && c <= 'Z'; }
bool isDigit(char c) { return c >= '0' && c <= '9'; }

} // namespace

bool isValidModuleName(const std::string& name)
{
    if (name.empty() || name.size() > 128 || !(isLower(name[0]) || isUpper(name[0]))) return false;
    for (const char c : name)
        if (!(isLower(c) || isUpper(c) || isDigit(c) || c == '_')) return false;
    return true;
}

bool isValidAlias(const std::string& alias)
{
    if (alias.empty() || alias.size() > 63 || !(isLower(alias[0]) || isDigit(alias[0]))) return false;
    for (const char c : alias)
        if (!(isLower(c) || isDigit(c) || c == '_' || c == '-')) return false;
    return true;
}

bool isValidDisplayName(const std::string& name)
{
    if (name.empty() || name.size() > 64) return false;
    for (const unsigned char c : name)
        if (c < 0x20 || c == 0x7F) return false;
    return true;
}

} // namespace logos::peering
