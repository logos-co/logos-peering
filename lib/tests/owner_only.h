#pragma once

#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <vector>
#endif

// Whether only the owner may use `path`: no group or other mode bits, or on
// Windows a DACL whose every entry grants the current user.
inline bool ownerOnly(const std::filesystem::path& path)
{
#ifdef _WIN32
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl,
                              nullptr, &descriptor) != ERROR_SUCCESS)
        return false;
    bool only = false;
    ACL_SIZE_INFORMATION info{};
    HANDLE token = nullptr;
    if (acl && GetAclInformation(acl, &info, sizeof info, AclSizeInformation) && info.AceCount > 0
        && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> user(size);
        only = size && GetTokenInformation(token, TokenUser, user.data(), size, &size);
        for (DWORD i = 0; only && i < info.AceCount; ++i) {
            void* ace = nullptr;
            only = GetAce(acl, i, &ace) && static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE
                   && EqualSid(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart,
                               reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
        }
        CloseHandle(token);
    }
    LocalFree(descriptor);
    return only;
#else
    namespace fs = std::filesystem;
    return (fs::status(path).permissions() & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none;
#endif
}
