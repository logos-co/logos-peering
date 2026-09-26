#include "logos/peering/fs.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <io.h>
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

#ifndef _WIN32
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
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (ec) {
        setError(error, "cannot restrict " + dir.string() + ": " + ec.message());
        return false;
    }
    return true;
}

bool writeFileAtomically(const fs::path& path, const std::string& content, std::string* error)
{
    const fs::path temp = path.string() + ".tmp";
#ifdef _WIN32
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.flush();
        if (!out) {
            setError(error, "cannot write " + temp.string());
            return false;
        }
    }
    std::error_code ec;
    fs::rename(temp, path, ec);
    if (ec) {
        setError(error, "cannot replace " + path.string() + ": " + ec.message());
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
    std::ofstream out(path, std::ios::binary | std::ios::app);
    out << line << '\n';
    if (!out) {
        setError(error, "cannot append to " + path.string());
        return false;
    }
    return true;
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
