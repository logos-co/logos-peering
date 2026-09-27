#include "logos/peering/fs.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <vector>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace logos::peering {
namespace {

void setError(std::string* error, const std::string& text)
{
    if (error) *error = text;
}

#ifdef _WIN32
std::string lastError()
{
    return "Windows error " + std::to_string(GetLastError());
}

// What 0600 and 0700 say on POSIX: a DACL whose one entry grants the current
// user, protected from its parent's inheritable entries.
class OwnerOnly {
public:
    explicit OwnerOnly(bool inheritable)
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return;
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> user(size);
        const bool known = size && GetTokenInformation(token, TokenUser, user.data(), size, &size);
        CloseHandle(token);
        if (!known) return;
        EXPLICIT_ACCESSW entry{};
        entry.grfAccessPermissions = FILE_ALL_ACCESS;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = inheritable ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
        if (SetEntriesInAclW(1, &entry, nullptr, &acl_) != ERROR_SUCCESS) return;
        ok_ = InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION)
              && SetSecurityDescriptorDacl(&descriptor_, TRUE, acl_, FALSE)
              && SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        attributes_ = {sizeof(SECURITY_ATTRIBUTES), &descriptor_, FALSE};
    }
    ~OwnerOnly()
    {
        if (acl_) LocalFree(acl_);
    }
    OwnerOnly(const OwnerOnly&) = delete;
    OwnerOnly& operator=(const OwnerOnly&) = delete;

    bool ok() const { return ok_; }
    SECURITY_ATTRIBUTES* attributes() { return &attributes_; }
    // Replaces an existing file's or directory's DACL with this one.
    bool apply(const fs::path& path) const
    {
        return ok_ && SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                            nullptr, nullptr, acl_, nullptr) == ERROR_SUCCESS;
    }

private:
    PACL acl_ = nullptr;
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
    bool ok_ = false;
};

bool writeAll(HANDLE file, const std::string& content)
{
    DWORD written = 0;
    return WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr)
           && written == content.size();
}
#else
bool writeAll(int fd, const std::string& content)
{
    const char* cursor = content.data();
    std::size_t left = content.size();
    while (left > 0) {
        const ssize_t written = ::write(fd, cursor, left);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        cursor += written;
        left -= static_cast<std::size_t>(written);
    }
    return true;
}
#endif

} // namespace

bool ensurePrivateDir(const fs::path& dir, std::string* error)
{
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        setError(error, "cannot create " + dir.string() + ": " + ec.message());
        return false;
    }
#ifdef _WIN32
    if (!OwnerOnly(true).apply(dir)) {
        setError(error, "cannot restrict " + dir.string() + ": " + lastError());
        return false;
    }
#else
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (ec) {
        setError(error, "cannot restrict " + dir.string() + ": " + ec.message());
        return false;
    }
#endif
    return true;
}

bool writeFileAtomically(const fs::path& path, const std::string& content, std::string* error)
{
    const fs::path temp = path.string() + ".tmp";
#ifdef _WIN32
    OwnerOnly owner(false);
    DeleteFileW(temp.c_str());
    const HANDLE file = owner.ok() ? CreateFileW(temp.c_str(), GENERIC_WRITE, 0, owner.attributes(), CREATE_NEW,
                                                 FILE_ATTRIBUTE_NORMAL, nullptr)
                                   : INVALID_HANDLE_VALUE;
    if (file == INVALID_HANDLE_VALUE) {
        setError(error, "cannot create " + temp.string() + ": " + lastError());
        return false;
    }
    const bool written = writeAll(file, content) && FlushFileBuffers(file);
    CloseHandle(file);
    if (!written || !MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        setError(error, "cannot write " + path.string() + ": " + lastError());
        DeleteFileW(temp.c_str());
        return false;
    }
    return true;
#else
    ::unlink(temp.c_str());
    const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        setError(error, "cannot create " + temp.string() + ": " + std::strerror(errno));
        return false;
    }
    const bool written = writeAll(fd, content) && ::fsync(fd) == 0;
    ::close(fd);
    if (!written || ::rename(temp.c_str(), path.c_str()) != 0) {
        setError(error, "cannot write " + path.string() + ": " + std::strerror(errno));
        ::unlink(temp.c_str());
        return false;
    }
    return true;
#endif
}

std::optional<std::string> readFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream content;
    content << in.rdbuf();
    return content.str();
}

bool appendLine(const fs::path& path, const std::string& line, std::string* error)
{
#ifdef _WIN32
    OwnerOnly owner(false);
    const HANDLE file = owner.ok() ? CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, owner.attributes(),
                                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)
                                   : INVALID_HANDLE_VALUE;
    if (file == INVALID_HANDLE_VALUE) {
        setError(error, "cannot open " + path.string() + ": " + lastError());
        return false;
    }
    const bool ok = writeAll(file, line + "\n");
    CloseHandle(file);
    if (!ok) setError(error, "cannot append to " + path.string());
    return ok;
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        setError(error, "cannot open " + path.string() + ": " + std::strerror(errno));
        return false;
    }
    const bool ok = writeAll(fd, line + "\n");
    ::close(fd);
    if (!ok) setError(error, "cannot append to " + path.string());
    return ok;
#endif
}

} // namespace logos::peering
