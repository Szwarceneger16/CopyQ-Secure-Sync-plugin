// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef __linux__
#error A separate Windows handle-based private state backend is required
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "state_store.h"
#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#ifdef CQS_STATE_TESTING
#include "../tests/state_hooks.h"
#define STATE_HOOK(p) do { if (testing::hook) testing::hook(testing::Point::p); } while (false)
#else
#define STATE_HOOK(p) do {} while (false)
#endif

namespace cqs::state {
namespace {
using crypto::Bytes;
using transaction::Record;
[[noreturn]] void fail(ErrorCode c, const char *text) { throw Error(c, text); }
[[noreturn]] void io() {
    if (errno == ENOENT) fail(ErrorCode::Missing, "Private state path is missing; not reinitialized");
    if (errno == ELOOP || errno == ENOTDIR) fail(ErrorCode::UnsafePath, "Unsafe private state path");
    fail(ErrorCode::Io, "Private state I/O failed");
}
class Fd {
public:
    explicit Fd(int fd) : fd_(fd) { if (fd < 0) io(); }
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(Fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};
struct Wiped { Bytes bytes; ~Wiped() { crypto::wipe(bytes); } };
struct stat statFd(int fd) { struct stat s{}; if (::fstat(fd, &s)) io(); return s; }
bool identity(const struct stat &a, const struct stat &b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
           a.st_uid == b.st_uid && a.st_gid == b.st_gid;
}
bool same(const struct stat &a, const struct stat &b) {
    return identity(a, b) && a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
void privateMode(const struct stat &s, bool dir) {
    if (s.st_uid != ::geteuid() || (s.st_mode & 07777) != (dir ? 0700 : 0600) ||
        (dir ? !S_ISDIR(s.st_mode) : (!S_ISREG(s.st_mode) || s.st_nlink != 1)))
        fail(ErrorCode::UnsafePath, "Private state requires owned 0700 directories and single-link 0600 files");
}
struct Link {
    Fd fd; int parent; std::string name; struct stat stamp;
};
void mapped(const Link &l, bool content = false) {
    struct stat named{};
    if (::fstatat(l.parent, l.name.c_str(), &named, AT_SYMLINK_NOFOLLOW))
        fail(ErrorCode::Changed, "Private state path changed");
    const auto s = statFd(l.fd.get());
    if (!identity(s, l.stamp) || !identity(named, l.stamp) || s.st_nlink == 0 ||
        (content && (!same(s, l.stamp) || !same(named, l.stamp))))
        fail(ErrorCode::Changed, "Private state entry changed");
}
Link directory(int parent, const std::string &name) {
    Fd fd(::openat(parent, name.c_str(), O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    const auto s = statFd(fd.get()); Link result{std::move(fd), parent, name, s}; mapped(result); return result;
}
Link pin(int dir, const std::string &name, dev_t device) {
    Fd fd(::openat(dir, name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    const auto s = statFd(fd.get()); privateMode(s, false);
    if (s.st_dev != device || s.st_size < 0) fail(ErrorCode::UnsafePath, "Unsafe private state inode");
    Link result{std::move(fd), dir, name, s}; mapped(result, true); return result;
}
std::string proc(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
void sync(int fd) { while (::fsync(fd)) { if (errno != EINTR) io(); } }
void writeAll(int fd, const Bytes &b) {
    std::size_t pos = 0;
    while (pos < b.size()) {
        auto n = ::write(fd, b.data()+pos, std::min<std::size_t>(16384, b.size()-pos));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail(ErrorCode::Io, "Private ciphertext write failed");
        pos += static_cast<std::size_t>(n);
    }
}
void linkFd(int source, int dest, const std::string &name) {
    int r = ::linkat(source, "", dest, name.c_str(), AT_EMPTY_PATH);
    if (r && (errno == EPERM || errno == ENOENT || errno == EINVAL))
        r = ::linkat(AT_FDCWD, proc(source).c_str(), dest, name.c_str(), AT_SYMLINK_FOLLOW);
    if (r) { if (errno == EEXIST) fail(ErrorCode::AlreadyInitialized, "Private record destination exists"); io(); }
}
std::string tempName() {
    const auto random = crypto::random(16); const char *hex = "0123456789abcdef";
    std::string out = ".cqs-record-";
    for (auto c : random) { out += hex[c >> 4]; out += hex[c & 15]; }
    return out + ".tmp";
}
// Remove ONLY our still-mapped ciphertext staging inode. Never delete a final
// record or an unknown replacement. Crash leftovers are inert, not auto-promoted.
struct StagingName {
    int dir, fd; std::string name;
    ~StagingName() {
        if (name.empty()) return;
        struct stat a{}, b{};
        if (!::fstat(fd, &a) && !::fstatat(dir, name.c_str(), &b, AT_SYMLINK_NOFOLLOW) && identity(a, b))
            ::unlinkat(dir, name.c_str(), 0);
    }
};
} // namespace

struct FileStore::Impl {
    Fd slash{::open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC)};
    std::vector<Link> chain;
    Wiped key;
    std::string binding;
    Limits limits;
    Protection protection;
    LeaseKind kind;
    std::mutex mutex;
    int leaseFd = -1;
    std::thread::id owner;
    pid_t process = 0;
    struct stat lockStamp{};
    Impl(const std::filesystem::path &path, std::string b, const Bytes &k, Limits l, Protection p, LeaseKind domain)
        : binding(std::move(b)), limits(l), protection(p),kind(domain) {
        if(kind!=LeaseKind::Record&&kind!=LeaseKind::Session)fail(ErrorCode::InvalidRecord,"Invalid lease domain");
        validateLimits(limits); validateBinding(binding);
        validateSecret(k, protection);
        const auto text = path.native();
        if (!path.is_absolute() || text.size() > 4096 || text.find('\0') != std::string::npos)
            fail(ErrorCode::UnsafePath, "Explicit absolute private directory required");
        int parent = slash.get();
        for (const auto &part : path.relative_path()) {
            auto name = part.native(); if (name.empty()) continue;
            if (name == "." || name == ".." || name.size() > 255 || chain.size() == 256)
                fail(ErrorCode::UnsafePath, "Invalid private directory component");
            chain.push_back(directory(parent, name)); parent = chain.back().fd.get();
        }
        if (chain.empty()) fail(ErrorCode::UnsafePath, "Filesystem root cannot hold private state");
        privateMode(chain.back().stamp, true); verify(); key.bytes = k;
    }
    int dir() const { return chain.back().fd.get(); }
    dev_t device() const { return chain.back().stamp.st_dev; }
    void verify() const { for (const auto &l : chain) mapped(l); }
    void requireLease() const {
        if (kind!=LeaseKind::Record || leaseFd < 0 || process != ::getpid() || owner != std::this_thread::get_id())
            fail(ErrorCode::LeaseRequired, "Private state operation requires this thread's lease");
        verify(); struct stat named{};
        if (::fstatat(dir(), LockName, &named, AT_SYMLINK_NOFOLLOW) ||
            !same(statFd(leaseFd), lockStamp) || !same(named, lockStamp))
            fail(ErrorCode::Changed, "Private state lock inode changed");
    }
    struct Loaded { Record record; Link file; };
    Loaded read() {
        requireLease(); auto file = pin(dir(), RecordName, device());
        if (static_cast<std::uintmax_t>(file.stamp.st_size) > limits.recordBytes + envelopeOverhead(protection))
            fail(ErrorCode::SizeLimit, "Private record file exceeds budget");
        STATE_HOOK(ReadPinned); mapped(file, true);
        Fd fd(::open(proc(file.fd.get()).c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
        if (!same(statFd(fd.get()), file.stamp)) fail(ErrorCode::Changed, "Private record changed before read");
        Bytes wire(static_cast<std::size_t>(file.stamp.st_size)); std::size_t pos = 0;
        while (pos < wire.size()) {
            const auto n = ::read(fd.get(), wire.data()+pos, std::min<std::size_t>(16384, wire.size()-pos));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) fail(ErrorCode::Changed, "Private record changed or failed during read");
            pos += static_cast<std::size_t>(n);
        }
        char extra; ssize_t n; do { n = ::read(fd.get(), &extra, 1); } while (n < 0 && errno == EINTR);
        if (n != 0 || !same(statFd(fd.get()), file.stamp)) fail(ErrorCode::Changed, "Private record changed during read");
        STATE_HOOK(ReadComplete); mapped(file, true); requireLease();
        auto record = unseal(key.bytes, binding, wire, limits, protection);
        mapped(file, true); requireLease();
        return {std::move(record), std::move(file)};
    }
    void write(const Bytes &wire, const Link *expected) {
        requireLease();
        const int raw = ::openat(dir(), ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (raw < 0 && (errno == EOPNOTSUPP || errno == EINVAL || errno == EISDIR || errno == ENOSYS))
            fail(ErrorCode::UnsupportedFilesystem, "Private filesystem lacks anonymous staging");
        Fd staged(raw); writeAll(staged.get(), wire); sync(staged.get());
        const auto s = statFd(staged.get());
        if (!S_ISREG(s.st_mode) || s.st_nlink || s.st_size != static_cast<off_t>(wire.size()) ||
            s.st_uid != ::geteuid() || (s.st_mode & 07777) != 0600)
            fail(ErrorCode::Io, "Invalid private staging inode");
        STATE_HOOK(StageSynced);
        StagingName temp{dir(), staged.get(), {}};
        struct stat stagedLinked{};
        if (expected) {
            temp.name = tempName(); linkFd(staged.get(), dir(), temp.name);
            stagedLinked = statFd(staged.get());
            STATE_HOOK(StageLinked);
        }
        STATE_HOOK(BeforePublish); requireLease();
        if (expected) {
            mapped(*expected, true);
            struct stat named{};
            if (::fstatat(dir(), temp.name.c_str(), &named, AT_SYMLINK_NOFOLLOW) ||
                !same(named, stagedLinked) || !same(statFd(staged.get()), stagedLinked) ||
                !identity(named, s) || named.st_nlink != 1 || named.st_size != s.st_size ||
                named.st_mtim.tv_sec != s.st_mtim.tv_sec || named.st_mtim.tv_nsec != s.st_mtim.tv_nsec)
                fail(ErrorCode::Changed, "Private staging mapping changed");
            if (::renameat(dir(), temp.name.c_str(), dir(), RecordName)) io();
            temp.name.clear();
        } else {
            linkFd(staged.get(), dir(), RecordName); // create-only initialization
        }
        try {
            const auto placed = statFd(staged.get());
            STATE_HOOK(Published);
            sync(staged.get()); sync(dir()); STATE_HOOK(DirectorySynced);
            requireLease(); struct stat named{};
            const auto current = statFd(staged.get());
            if (::fstatat(dir(), RecordName, &named, AT_SYMLINK_NOFOLLOW) ||
                !same(current, placed) || !same(current, named) || !identity(s, current) || current.st_size != s.st_size ||
                current.st_nlink != 1 || current.st_mtim.tv_sec != s.st_mtim.tv_sec ||
                current.st_mtim.tv_nsec != s.st_mtim.tv_nsec)
                fail(ErrorCode::Changed, "Committed private record changed");
        } catch (...) {
            fail(ErrorCode::CommitUnconfirmed, "Private record may be committed; release lease and reload");
        }
    }
};
struct FileStore::FileLease final : Store::Lease {
    std::shared_ptr<Impl> state;
    Fd fd;
    pid_t process;
    FileLease(std::shared_ptr<Impl> s, Fd &&f) : state(std::move(s)), fd(std::move(f)), process(::getpid()) {}
    ~FileLease() override {
        std::lock_guard<std::mutex> guard(state->mutex);
        // Explicit unlock in a forked child would unlock the parent's shared OFD.
        if (process == ::getpid()) { ::flock(fd.get(), LOCK_UN); state->leaseFd = -1; }
    }
};
FileStore::FileStore(const std::filesystem::path &path, std::string binding, const Bytes &key, Limits l, Protection p, LeaseKind domain)
    : impl_(std::make_shared<Impl>(path, std::move(binding), key, l, p,domain)) {}
FileStore::~FileStore() = default;
std::unique_ptr<transaction::Store::Lease> FileStore::lock() {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) return nullptr;
    s.verify(); if (s.leaseFd >= 0) return nullptr;
    const auto name=s.kind==LeaseKind::Session?SessionLockName:LockName;
    int created = ::openat(s.dir(), name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (created >= 0) { Fd newFile(created); privateMode(statFd(newFile.get()), false); sync(newFile.get()); sync(s.dir()); }
    else if (errno != EEXIST) io();
    auto pinned = pin(s.dir(), name, s.device());
    if (pinned.stamp.st_size != 0) fail(ErrorCode::UnsafePath, "Private lock must be an empty file");
    Fd fd(::open(proc(pinned.fd.get()).c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (::flock(fd.get(), LOCK_EX | LOCK_NB)) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) return nullptr;
        io();
    }
    mapped(pinned, true); s.verify();
    if (!same(statFd(fd.get()), pinned.stamp)) fail(ErrorCode::Changed, "Private lock changed");
    auto lease = std::make_unique<FileLease>(impl_, std::move(fd));
    s.leaseFd = lease->fd.get(); s.lockStamp = pinned.stamp;
    s.owner = std::this_thread::get_id(); s.process = ::getpid(); return lease;
}
Record FileStore::load() {
    std::unique_lock<std::mutex> guard(impl_->mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation is in progress");
    return impl_->read().record;
}
void FileStore::initialize() { initialize(Record{1, impl_->binding, 0, {}, {}}); }
void FileStore::checkInitializable() {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation is in progress");
    s.requireLease();
    struct stat existing{};
    if (!::fstatat(s.dir(), RecordName, &existing, AT_SYMLINK_NOFOLLOW))
        fail(ErrorCode::AlreadyInitialized, "Private record exists; never reset automatically");
    if (errno != ENOENT) io();
    // Refuse a legacy Python state directory or orphaned state artifacts. Setup
    // must select an empty dedicated directory, never silently start over.
    const int raw = ::openat(s.dir(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0) io();
    DIR *stream = ::fdopendir(raw);
    if (!stream) { const int saved = errno; ::close(raw); errno = saved; io(); }
    struct Close { void operator()(DIR *d) const { ::closedir(d); } };
    std::unique_ptr<DIR, Close> listing(stream);
    for (;;) {
        errno = 0; const auto *entry = ::readdir(stream);
        if (!entry) { if (errno) io(); break; }
        const std::string name(entry->d_name);
        if (name != "." && name != ".." && name != LockName && name!=SessionLockName)
            fail(ErrorCode::InvalidRecord, "Private setup directory contains existing state or unknown files");
    }
}
void FileStore::initialize(const Record &initial) {
    checkInitializable();
    auto &s=*impl_;std::unique_lock<std::mutex> guard(s.mutex,std::try_to_lock);
    if(!guard.owns_lock())fail(ErrorCode::Busy,"Private state operation in progress");
    s.requireLease();
    s.write(seal(s.key.bytes, s.binding, initial, s.limits, s.protection), nullptr);
}
void FileStore::commit(const Record &expected, const Record &replacement) {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation is in progress");
    s.requireLease();
    if (expected.binding != s.binding || replacement.binding != s.binding)
        fail(ErrorCode::WrongBinding, "Commit belongs to another binding");
    if (expected.generation == std::numeric_limits<std::uint64_t>::max() ||
        replacement.generation != expected.generation + 1)
        fail(ErrorCode::Generation, "Private state generation must advance exactly once");
    auto current = s.read();
    Wiped wanted{serialize(expected, s.limits)}, actual{serialize(current.record, s.limits)};
    if (wanted.bytes != actual.bytes) fail(ErrorCode::Stale, "Whole-record compare-and-swap failed");
    // Encrypt before opening staging. The old authoritative record remains intact
    // for every failure before atomic rename; no plaintext ever reaches write().
    const auto wire = seal(s.key.bytes, s.binding, replacement, s.limits, s.protection);
    s.write(wire, &current.file);
}
void FileStore::transition(const Record &expected, const Record &replacement, const Bytes &newSecret, Protection newProtection) {
    auto &s = *impl_; std::unique_lock<std::mutex> guard(s.mutex, std::try_to_lock);
    if (!guard.owns_lock()) fail(ErrorCode::Busy, "Private state operation in progress");
    s.requireLease(); validateSecret(newSecret, newProtection); validateBinding(replacement.binding);
    if (expected.binding != s.binding) fail(ErrorCode::WrongBinding, "Transition belongs to another private profile");
    if (expected.generation == std::numeric_limits<std::uint64_t>::max() || replacement.generation != expected.generation + 1)
        fail(ErrorCode::Generation, "Private state generation must advance exactly once");
    auto current = s.read();
    Wiped wanted{serialize(expected, s.limits)}, actual{serialize(current.record, s.limits)}, nextSecret{newSecret};
    if (wanted.bytes != actual.bytes) fail(ErrorCode::Stale, "Whole-record compare-and-swap failed");
    auto nextBinding = replacement.binding;
    const auto wire = seal(nextSecret.bytes, nextBinding, replacement, s.limits, newProtection);
    s.write(wire, &current.file);
    crypto::wipe(s.key.bytes); s.key.bytes = std::move(nextSecret.bytes);
    s.binding = std::move(nextBinding); s.protection = newProtection;
}
} // namespace cqs::state
