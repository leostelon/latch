import Foundation
import Darwin

/// All mutable privileged state is beneath root-owned, non-writable directories.
/// openat/O_NOFOLLOW and atomic rename prevent following user-created links.
enum SecureStore {
    static let directory = "/Library/Application Support/EnsureVPN"
    static let helperPath = "/Library/PrivilegedHelperTools/dev.ensurevpn.helper"
    static let launchPath = "/Library/LaunchDaemons/dev.ensurevpn.helper.plist"

    static func verifyDirectory(_ path: String, create: Bool = false) throws {
        var current = ""
        for part in path.split(separator: "/") {
            current += "/" + part
            var info = stat()
            var created = false
            if lstat(current, &info) != 0 {
                guard errno == ENOENT, create, mkdir(current, 0o755) == 0 else {
                    throw HelperFailure("Cannot access the protected helper directory: \(current).")
                }
                created = true
                guard lstat(current, &info) == 0 else { throw HelperFailure("Could not inspect \(current).") }
            }
            guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == 0, info.st_mode & 0o022 == 0 else {
                throw HelperFailure("Unsafe ownership, permissions, or symbolic link at \(current).")
            }
            if created {
                // The process umask is 077 for private files. Directories must still
                // permit traversal so the unprivileged app can read status.json.
                let descriptor = open(current, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard descriptor >= 0 else { throw HelperFailure("Cannot set helper directory permissions.") }
                defer { close(descriptor) }
                guard fchmod(descriptor, 0o755) == 0 else { throw HelperFailure("Cannot make helper status readable.") }
            }
        }
    }

    static func directoryFD(_ path: String = directory, create: Bool = true) throws -> Int32 {
        try verifyDirectory(path, create: create)
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw HelperFailure("Could not open protected helper storage.") }
        return descriptor
    }

    static func validateFile(_ fd: Int32, readableByUser: Bool) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0,
              info.st_nlink == 1, info.st_mode & 0o022 == 0,
              readableByUser || info.st_mode & 0o077 == 0 else {
            throw HelperFailure("A privileged helper file has unsafe ownership or permissions.")
        }
    }

    static func read(_ name: String, maximum: Int = 262_144, readableByUser: Bool = false) throws -> Data? {
        guard !name.contains("/") else { throw HelperFailure("Invalid helper storage name.") }
        let dir = try directoryFD(); defer { close(dir) }
        let file = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if file < 0 && errno == ENOENT { return nil }
        guard file >= 0 else { throw HelperFailure("Could not read protected helper state.") }
        defer { close(file) }
        try validateFile(file, readableByUser: readableByUser)
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            guard count >= 0 else { throw HelperFailure("Failed to read helper state.") }
            if count == 0 { break }
            guard data.count + count <= maximum else { throw HelperFailure("Helper state is too large.") }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    static func write(_ data: Data, name: String, directory path: String = directory, mode: mode_t = 0o600) throws {
        guard !name.contains("/"), !name.isEmpty else { throw HelperFailure("Invalid helper storage name.") }
        let dir = try directoryFD(path); defer { close(dir) }
        var existing = stat()
        if fstatat(dir, name, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG, existing.st_uid == 0,
                  existing.st_nlink == 1, existing.st_mode & 0o022 == 0 else {
                throw HelperFailure("Refusing to replace an unsafe helper file: \(name).")
            }
        } else if errno != ENOENT { throw HelperFailure("Cannot inspect helper destination.") }
        let temporary = ".\(name).\(UUID().uuidString)"
        let file = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw HelperFailure("Could not create a protected temporary file.") }
        defer { close(file); unlinkat(dir, temporary, 0) }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < data.count {
                let result = Darwin.write(file, raw.baseAddress!.advanced(by: offset), data.count - offset)
                guard result > 0 else { throw HelperFailure("Could not write helper state.") }
                offset += result
            }
        }
        guard fchmod(file, mode) == 0, fsync(file) == 0, renameat(dir, temporary, dir, name) == 0 else {
            throw HelperFailure("Could not commit protected helper state.")
        }
        _ = fsync(dir)
    }

    static func remove(_ name: String) throws {
        let dir = try directoryFD(); defer { close(dir) }
        var info = stat()
        guard fstatat(dir, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return }
            throw HelperFailure("Could not inspect helper state.")
        }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0, info.st_nlink == 1 else {
            throw HelperFailure("Refusing to remove an unsafe helper file.")
        }
        guard unlinkat(dir, name, 0) == 0 else { throw HelperFailure("Could not remove helper state.") }
    }

    static func locked<T>(_ operation: () throws -> T) throws -> T {
        let dir = try directoryFD(); defer { close(dir) }
        let file = openat(dir, "operation.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw HelperFailure("Could not open helper operation lock.") }
        defer { close(file) }
        try validateFile(file, readableByUser: false)
        let deadline = Date().addingTimeInterval(20)
        while flock(file, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EWOULDBLOCK, Date() < deadline else { throw HelperFailure("Another helper operation is still running. Try again shortly.") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        defer { flock(file, LOCK_UN) }
        return try operation()
    }
}
