// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef __linux__
#error A separate handle-based native blob reader is required on this platform
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "native_blob.h"
#include <sys/mman.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <filesystem>
#include <utility>
namespace cqs::native {
namespace {
[[noreturn]] void fail() { throw crypto::Error("Native blob path, type, size or stability check failed"); }
class Fd {
public:
    explicit Fd(int fd) : fd_(fd) { if (fd < 0) fail(); }
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(Fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd(const Fd &) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};
struct stat stamp(int fd) { struct stat s{}; if (::fstat(fd, &s) != 0) fail(); return s; }
bool same(const struct stat &a, const struct stat &b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink &&
        a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
        a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
        a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
bool sameDirectory(const struct stat &a, const struct stat &b) {
    // Sibling creation/removal changes directory size, link count and times.
    // It does not retarget this pinned path or change its access policy. Check
    // name mappings, inode/type, owner and permissions without a global /tmp
    // snapshot requirement. The key's own full metadata remains strict.
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_gid == b.st_gid;
}
struct Link { Fd fd; int parent; std::string name; struct stat initial; };
void verify(const std::vector<Link> &links) {
    for (const auto &link : links) {
        struct stat s{};
        if (::fstatat(link.parent, link.name.c_str(), &s, AT_SYMLINK_NOFOLLOW) != 0) fail();
        const auto checked = S_ISDIR(link.initial.st_mode) ? sameDirectory : same;
        if (!checked(s, link.initial) || !checked(stamp(link.fd.get()), link.initial)) fail();
    }
}
struct Wipe { crypto::Bytes bytes; ~Wipe() { crypto::wipe(bytes); } };
}
QByteArray readNativeBlob(const QString &filename,std::size_t maximum) {
    const auto file=std::filesystem::u8path(filename.toUtf8().toStdString());
    const auto text = file.native();
    if (!file.is_absolute() || text.size() > 4096 || text.find('\0') != std::string::npos) fail();
    std::vector<std::string> parts;
    for (const auto &component : file.relative_path()) {
        const auto p = component.native();
        if (p.empty() || p == "." || p == ".." || p.size() > 255 || parts.size() == 256) fail();
        parts.push_back(p);
    }
    if (parts.empty()) fail();
    Fd root(::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    int parent = root.get();
    std::vector<Link> links;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const bool last = i + 1 == parts.size();
        Fd fd(::openat(parent, parts[i].c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC | (last ? 0 : O_DIRECTORY)));
        const auto s = stamp(fd.get());
        if (last) {
            if (!S_ISREG(s.st_mode) || s.st_nlink != 1 || s.st_uid != ::geteuid() ||
                (s.st_mode & 0022) != 0 || (s.st_mode & 07000) != 0 || s.st_size < 0 || std::uint64_t(s.st_size)>maximum) fail();
            const auto directory = stamp(parent);
            if (directory.st_uid != ::geteuid() || (directory.st_mode & 0022) != 0) fail();
        } else if (!S_ISDIR(s.st_mode)) fail();
        links.push_back({std::move(fd), parent, parts[i], s});
        parent = links.back().fd.get();
    }
    verify(links);
    // Trusted procfs reopens the pinned, checked inode. It does NOT follow a
    // transport- or user-provided symlink and never opens FIFO/device content.
    const auto pinned = "/proc/self/fd/" + std::to_string(parent);
    Fd input(::open(pinned.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (!same(stamp(input.get()), links.back().initial)) fail();

    Wipe output; output.bytes.resize(std::size_t(links.back().initial.st_size)+1);
    std::size_t total = 0;
    while (total < output.bytes.size()) {
        const auto n = ::read(input.get(), output.bytes.data() + total, output.bytes.size() - total);
        if (n < 0) { if (errno == EINTR) continue; fail(); }
        if (!n) break;
        total += static_cast<std::size_t>(n);
    }

    if (total != std::size_t(links.back().initial.st_size) || !same(stamp(input.get()), links.back().initial)) fail();
    verify(links);
    return QByteArray(reinterpret_cast<const char *>(output.bytes.data()),qsizetype(total));
}
QByteArray withFrozenCiphertext(const QByteArray &bytes,const std::function<QByteArray(const QString &)> &convert) {
    Fd fd(::memfd_create("cqs-native-ciphertext",MFD_CLOEXEC|MFD_ALLOW_SEALING));
    std::size_t done=0;while(done<std::size_t(bytes.size())) {
        const auto n=::write(fd.get(),bytes.constData()+done,std::size_t(bytes.size())-done);
        if(n<0&&errno==EINTR)continue;if(n<=0)fail();done+=std::size_t(n);
    }
    if(::fcntl(fd.get(),F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)<0)fail();
    return convert(QStringLiteral("/proc/self/fd/")+QString::number(fd.get()));
}
} // namespace cqs::native
