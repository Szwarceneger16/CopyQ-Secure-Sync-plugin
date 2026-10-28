// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef __linux__
#error This backend requires Linux; do not substitute unchecked path-based I/O
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "storage.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#ifdef CQS_STORAGE_TESTING
#include "../tests/storage_hooks.h"
#define CQS_HOOK(point) do { if (testing::hook) testing::hook(testing::Point::point); } while (false)
#else
#define CQS_HOOK(point) do {} while (false)
#endif

namespace cqs::storage {
namespace {
[[noreturn]] void fail(ErrorCode code, const char *message) { throw Error(code, message); }
[[noreturn]] void ioError() {
    if (errno == ENOENT || errno == ESTALE)
        fail(ErrorCode::Unavailable, "Transport entry unavailable; retry a complete scan");
    if (errno == ELOOP || errno == ENOTDIR)
        fail(ErrorCode::UnsafeEntry, "Unsafe transport path component");
    fail(ErrorCode::Io, "Transport I/O operation failed");
}
class Fd final {
public:
    explicit Fd(int fd) : fd_(fd) { if (fd < 0) ioError(); }
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(Fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd &operator=(Fd &&) = delete;
    Fd(const Fd &) = delete;
    int get() const noexcept { return fd_; }
private:
    int fd_;
};
struct stat status(int fd) {
    struct stat out{};
    if (::fstat(fd, &out) != 0) ioError();
    return out;
}
bool identity(const struct stat &a, const struct stat &b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
           a.st_mode == b.st_mode && a.st_uid == b.st_uid && a.st_gid == b.st_gid;
}
bool same(const struct stat &a, const struct stat &b) {
    return identity(a, b) && a.st_size == b.st_size && a.st_nlink == b.st_nlink &&
           a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
           a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
void owned(const struct stat &s) {
    if (s.st_uid != ::geteuid() || (s.st_mode & 0022) != 0)
        fail(ErrorCode::UnsafeEntry, "Transport entry must be owned by this user and not broadly writable");
}
struct Link {
    Fd fd;
    int parent;
    std::string name;
    struct stat stamp;
};
void mapped(const Link &link, bool unchanged = false) {
    struct stat byName{};
    if (::fstatat(link.parent, link.name.c_str(), &byName, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT || errno == ENOTDIR)
            fail(ErrorCode::Changed, "Transport path changed during operation");
        ioError();
    }
    const auto byHandle = status(link.fd.get());
    if (!identity(byName, link.stamp) || !identity(byHandle, link.stamp) ||
        byHandle.st_nlink == 0 || (unchanged &&
        (!same(byName, link.stamp) || !same(byHandle, link.stamp))))
        fail(ErrorCode::Changed, "Transport entry changed during operation");
}
Link directory(int parent, const std::string &name) {
    Fd fd(::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    const auto stamp = status(fd.get());
    if (!S_ISDIR(stamp.st_mode) || stamp.st_nlink == 0)
        fail(ErrorCode::UnsafeEntry, "Transport component is not a directory");
    Link out{std::move(fd), parent, name, stamp};
    mapped(out);
    return out;
}
void sameFilesystem(const struct stat &s, dev_t device) {
    if (s.st_dev != device)
        fail(ErrorCode::UnsafeEntry, "Nested transport mounts are not supported");
}
// Each name is a single component from readdir, never a path from JSON.
std::vector<std::string> names(int fd, std::size_t &remaining) {
    const int duplicate = ::openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (duplicate < 0) ioError();
    DIR *raw = ::fdopendir(duplicate); // a fresh open description, not dup(fd)
    if (!raw) { const int saved = errno; ::close(duplicate); errno = saved; ioError(); }
    struct CloseDir { void operator()(DIR *p) const { ::closedir(p); } };
    std::unique_ptr<DIR, CloseDir> stream(raw);
    std::set<std::string> sorted;
    for (;;) {
        errno = 0;
        const auto *entry = ::readdir(stream.get());
        if (!entry) { if (errno) ioError(); break; }
        const std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (!remaining) fail(ErrorCode::ScanLimit, "Transport directory entry budget exceeded");
        --remaining;
        if (!sorted.insert(name).second)
            fail(ErrorCode::Changed, "Transport directory changed while listing");
    }
    return {sorted.begin(), sorted.end()};
}
void validDevice(const std::string &name) {
    try { (void)history::makeId(name, 1); }
    catch (const history::Error &) {
        fail(ErrorCode::UnsafeEntry, "Unexpected transport device directory");
    }
}
std::string eventId(const std::string &device, const std::string &name) {
    if (name.size() != 16 || name.compare(12, 4, ".cqs") != 0)
        fail(ErrorCode::UnsafeEntry, "Unexpected event name or conflict copy; not skipped");
    std::uint64_t sequence = 0;
    for (std::size_t i = 0; i < 12; ++i) {
        if (name[i] < '0' || name[i] > '9')
            fail(ErrorCode::UnsafeEntry, "Noncanonical event filename");
        sequence = sequence * 10 + static_cast<unsigned>(name[i] - '0');
    }
    try { return history::makeId(device, sequence); }
    catch (const history::Error &) { fail(ErrorCode::UnsafeEntry, "Invalid event filename identity"); }
}
Link pinFile(int parent, const std::string &name, dev_t device) {
    // O_PATH examines the inode WITHOUT opening FIFO/device content. Even a
    // replacement between name enumeration and this call cannot make us open
    // a device or wait on a FIFO. A symlink itself is opened, then rejected.
    Fd fd(::openat(parent, name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    const auto s = status(fd.get());
    if (!S_ISREG(s.st_mode) || s.st_nlink != 1 || s.st_size < 0)
        fail(ErrorCode::UnsafeEntry, "Event must be a single-link regular file");
    owned(s);
    sameFilesystem(s, device);
    Link out{std::move(fd), parent, name, s};
    mapped(out, true);
    return out;
}
std::string procName(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
std::string readFile(const Link &file) {
    mapped(file, true);
    // This is a trusted kernel descriptor reference, NOT a symlink supplied by
    // the transport. It reopens the already checked regular inode, not its name.
    Fd input(::open(procName(file.fd.get()).c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (!same(status(input.get()), file.stamp))
        fail(ErrorCode::Changed, "Event changed before content read");
    const auto size = static_cast<std::size_t>(file.stamp.st_size);
    std::string out;
    out.reserve(size);
    std::array<char, 16384> chunk{};
    for (;;) {
        const auto count = std::min(chunk.size(), size - out.size() + 1);
        const auto n = ::read(input.get(), chunk.data(), count);
        if (n < 0) { if (errno == EINTR) continue; ioError(); }
        if (!n) break;
        if (static_cast<std::size_t>(n) > size - out.size())
            fail(ErrorCode::Changed, "Event grew during content read");
        out.append(chunk.data(), static_cast<std::size_t>(n));
        CQS_HOOK(ReadChunk);
    }
    if (out.size() != size || !same(status(input.get()), file.stamp))
        fail(ErrorCode::Changed, "Event changed during content read");
    mapped(file, true);
    return out;
}
void syncFd(int fd) {
    while (::fsync(fd) != 0) { if (errno != EINTR) ioError(); }
}
void writeAll(int fd, std::string_view data) {
    while (!data.empty()) {
        const auto n = ::write(fd, data.data(), std::min<std::size_t>(data.size(), 16384));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail(ErrorCode::Io, "Event write failed");
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}
} // namespace

struct Directory::Impl {
    Fd slash{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    std::vector<Link> chain;
    explicit Impl(const std::filesystem::path &root) {
        const auto text = root.native();
        if (!root.is_absolute() || text.size() > 4096 || text.find('\0') != std::string::npos)
            fail(ErrorCode::InvalidPath, "An absolute local transport root is required");
        int parent = slash.get();
        for (const auto &part : root.relative_path()) {
            const auto name = part.native();
            if (name.empty()) continue; // trailing separator
            if (name == "." || name == ".." || name.size() > 255 || chain.size() == 256)
                fail(ErrorCode::InvalidPath, "Invalid transport root component");
            chain.push_back(directory(parent, name));
            parent = chain.back().fd.get();
        }
        if (chain.empty()) fail(ErrorCode::InvalidPath, "Filesystem root is not a transport folder");
        owned(chain.back().stamp);
        const auto device = chain.back().stamp.st_dev;
        chain.push_back(directory(parent, "events"));
        owned(chain.back().stamp);
        sameFilesystem(chain.back().stamp, device);
        verify();
    }
    int eventsFd() const { return chain.back().fd.get(); }
    void verify() const { for (const auto &link : chain) mapped(link); }
};
Directory::Directory(const std::filesystem::path &root) : impl_(std::make_unique<Impl>(root)) {}
Directory::~Directory() = default;
void Directory::confirm(const crypto::Bytes &key,const events::Envelope &envelope,events::Limits limits) const {
    const auto event=events::decode(key,envelope,limits);impl_->verify();
    auto dir=directory(impl_->eventsFd(),event.revision.device);owned(dir.stamp);
    const auto volume=status(impl_->eventsFd()).st_dev;sameFilesystem(dir.stamp,volume);
    auto file=pinFile(dir.fd.get(),event.revision.id.substr(event.revision.device.size()+1)+".cqs",volume);
    if(file.stamp.st_size<0 || static_cast<std::uintmax_t>(file.stamp.st_size)!=envelope.bytes.size())
        fail(ErrorCode::Changed,"Reserved ciphertext size differs");
    if(readFile(file)!=envelope.bytes)fail(ErrorCode::Changed,"Reserved ciphertext differs");
    // pinFile holds O_PATH to reject special entries without opening them.
    // Reopen that checked inode through the kernel fd namespace for fsync.
    Fd durable(::open(procName(file.fd.get()).c_str(),O_RDONLY|O_NONBLOCK|O_CLOEXEC));
    if(!same(status(durable.get()),file.stamp))fail(ErrorCode::Changed,"Reserved ciphertext changed before confirmation");
    syncFd(durable.get());syncFd(dir.fd.get());syncFd(impl_->eventsFd());
    if(!same(status(durable.get()),file.stamp))fail(ErrorCode::Changed,"Reserved ciphertext changed during confirmation");
    mapped(file,true);mapped(dir);impl_->verify();
}

events::AuthenticatedHistory Directory::scan(const crypto::Bytes &key, Limits limits) const {
    const Limits ceiling;
    if (!limits.entries || !limits.devices || limits.entries > ceiling.entries || limits.devices > ceiling.devices)
        fail(ErrorCode::InvalidLimits, "Invalid transport scan limits");
    // Reuse reader validation even for an empty directory; never silently accept
    // an invalid key or elevated byte ceilings just because no files were found.
    (void)events::AuthenticatedHistory(key, {}, limits.reader);
    impl_->verify();
    const auto eventsStamp = status(impl_->eventsFd());
    std::size_t remaining = limits.entries, totalBytes = 0;
    auto deviceNames = names(impl_->eventsFd(), remaining);
    if (deviceNames.size() > limits.devices)
        fail(ErrorCode::ScanLimit, "Too many transport device directories");
    std::vector<Link> dirs;
    struct Input { Link file; std::string id; std::string bytes; };
    std::vector<Input> input;
    for (const auto &name : deviceNames) {
        validDevice(name);
        dirs.push_back(directory(impl_->eventsFd(), name));
        const auto &dir = dirs.back();
        owned(dir.stamp);
        sameFilesystem(dir.stamp, eventsStamp.st_dev);
        for (const auto &filename : names(dir.fd.get(), remaining)) {
            const auto id = eventId(name, filename);
            if (input.size() == limits.reader.events)
                fail(ErrorCode::ScanLimit, "Too many transport event files");
            auto file = pinFile(dir.fd.get(), filename, eventsStamp.st_dev);
            const auto size = static_cast<std::uintmax_t>(file.stamp.st_size);
            if (size > limits.reader.eventBytes || size > limits.reader.historyBytes - totalBytes)
                fail(ErrorCode::ScanLimit, "Transport wire byte budget exceeded");
            totalBytes += static_cast<std::size_t>(size);
            input.push_back({std::move(file), id, {}});
        }
    }
    CQS_HOOK(FilePinned);
    for (auto &item : input) item.bytes = readFile(item.file);
    CQS_HOOK(ScanRead);
    std::vector<events::Envelope> envelopes;
    envelopes.reserve(input.size());
    for (const auto &item : input) envelopes.push_back({item.id, item.bytes});
    events::AuthenticatedHistory result(key, envelopes, limits.reader);
    CQS_HOOK(ScanAuthenticated);
    // Recheck every inode AND its name, not only the last file read. In-place
    // writes do not necessarily change the parent directory timestamp.
    for (const auto &item : input) mapped(item.file, true);
    for (const auto &dir : dirs) mapped(dir, true);
    if (!same(status(impl_->eventsFd()), eventsStamp))
        fail(ErrorCode::Changed, "Transport devices changed during scan");
    impl_->verify();
    return result;
}

void Directory::checkPublicationDevice(const std::string &device) const {
    (void)history::makeId(device,1);impl_->verify();
    const Limits ceiling;std::size_t remaining=ceiling.entries;
    const auto devices=names(impl_->eventsFd(),remaining);
    if(devices.size()>ceiling.devices || (devices.size()==ceiling.devices&&std::find(devices.begin(),devices.end(),device)==devices.end()))
        fail(ErrorCode::ScanLimit,"No transport device slot for publication");
    impl_->verify();
}
void Directory::checkPublicationStaging(const std::filesystem::path &privateStaging) const {
    if(!privateStaging.empty())fail(ErrorCode::InvalidPath,"Linux publication uses anonymous staging");
    impl_->verify();
}
void Directory::publish(const crypto::Bytes &key, const events::Envelope &envelope,
                        events::Limits limits, const std::filesystem::path &privateStaging) const {
    if (!privateStaging.empty())
        fail(ErrorCode::InvalidPath, "Linux publication uses anonymous staging, not an alternate folder");
    (void)events::AuthenticatedHistory(key, {}, limits);
    if (!limits.events || envelope.bytes.size() > limits.eventBytes || envelope.bytes.size() > limits.historyBytes)
        fail(ErrorCode::ScanLimit, "Publication exceeds the event budget");
    const std::string wire(envelope.bytes); // the same bytes are verified and written
    limits.plaintextBytes = std::min(limits.plaintextBytes, limits.historyPlaintextBytes);
    auto decoded = events::decode(key, {envelope.expectedId, wire}, limits);
    const auto device = decoded.revision.device;checkPublicationDevice(device);
    const auto filename = decoded.revision.id.substr(device.size() + 1) + ".cqs";
    // Do not retain plaintext payloads during filesystem writes.
    for (auto &item : decoded.items) std::fill(item.begin(), item.end(), '\0');
    decoded.items.clear();
    impl_->verify();
    if (::mkdirat(impl_->eventsFd(), device.c_str(), 0700) != 0 && errno != EEXIST) ioError();
    auto dir = directory(impl_->eventsFd(), device);
    owned(dir.stamp);
    sameFilesystem(dir.stamp, status(impl_->eventsFd()).st_dev);
    // Also persists a device directory left by an interrupted earlier publisher.
    syncFd(impl_->eventsFd());
    const int raw = ::openat(dir.fd.get(), ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (raw < 0 && (errno == EOPNOTSUPP || errno == EINVAL || errno == EISDIR || errno == ENOSYS))
        fail(ErrorCode::UnsupportedFilesystem, "Transport filesystem lacks anonymous staging support");
    Fd temporary(raw);
    writeAll(temporary.get(), wire);
    CQS_HOOK(PublishWritten);
    syncFd(temporary.get());
    const auto staged = status(temporary.get());
    if (!S_ISREG(staged.st_mode) || staged.st_nlink != 0 || staged.st_size != static_cast<off_t>(wire.size()))
        fail(ErrorCode::Io, "Anonymous event staging failed");
    CQS_HOOK(PublishReady);
    impl_->verify();
    mapped(dir);
    // O_TMPFILE has no attacker-replaceable source pathname and no partial final
    // name. linkat atomically creates a name, never replaces an existing one.
    int linked = ::linkat(temporary.get(), "", dir.fd.get(), filename.c_str(), AT_EMPTY_PATH);
    if (linked != 0 && (errno == EPERM || errno == ENOENT || errno == EINVAL)) {
        // Unprivileged processes may not use AT_EMPTY_PATH. procfs is trusted;
        // this follows our own pinned fd, not any transport-provided symlink.
        linked = ::linkat(AT_FDCWD, procName(temporary.get()).c_str(),
                          dir.fd.get(), filename.c_str(), AT_SYMLINK_FOLLOW);
    }
    if (linked != 0) {
        if (errno == EEXIST) fail(ErrorCode::AlreadyExists, "Event ID already exists; never overwritten");
        ioError();
    }
    try {
        const auto linkedStamp = status(temporary.get());
        // Linking changes ctime/nlink but not mtime or the file contents.
        if (!identity(linkedStamp, staged) || linkedStamp.st_size != staged.st_size ||
            linkedStamp.st_nlink != 1 || linkedStamp.st_mtim.tv_sec != staged.st_mtim.tv_sec ||
            linkedStamp.st_mtim.tv_nsec != staged.st_mtim.tv_nsec)
            fail(ErrorCode::Changed, "Published event changed at link time");
        CQS_HOOK(PublishLinked);
        syncFd(dir.fd.get());
        impl_->verify();
        mapped(dir);
        struct stat published{};
        if (::fstatat(dir.fd.get(), filename.c_str(), &published, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same(published, linkedStamp) || !same(status(temporary.get()), linkedStamp))
            fail(ErrorCode::Changed, "Published event identity changed");
    } catch (...) {
        // NEVER unlink a published name, including after a durability error.
        fail(ErrorCode::PublishedUnconfirmed, "Event may be published; durability or identity unconfirmed");
    }
}
} // namespace cqs::storage
