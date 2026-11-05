import Foundation
import Darwin

struct HelperFailure: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

struct CommandResult {
    let output: String
    let error: String
    let status: Int32
}

private final class OutputBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var exceededLimit = false
    private var readFailed = false
    func append(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        if bytes.count + data.count <= 262_144 { bytes.append(data) }
        else { exceededLimit = true }
    }
    func markReadFailure() { lock.lock(); readFailed = true; lock.unlock() }
    func result() throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard !exceededLimit else { throw HelperFailure("A system command returned too much data; no protection claim can be made.") }
        guard !readFailed else { throw HelperFailure("Could not read a complete system command response; protection cannot be verified.") }
        return String(decoding: bytes, as: UTF8.self)
    }
}

enum CommandRunner {
    static func run(_ executable: String, _ arguments: [String], input: Data? = nil,
                    timeout: TimeInterval = 8, requireSuccess: Bool = true) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        let outPipe = Pipe(), errPipe = Pipe(), inPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        process.standardInput = input == nil ? FileHandle.nullDevice : inPipe
        let ended = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in ended.signal() }
        let readers = DispatchGroup()
        let output = OutputBuffer(), error = OutputBuffer()
        try process.run()
        for (pipe, buffer) in [(outPipe, output), (errPipe, error)] {
            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { readers.leave() }
                while true {
                    do {
                        guard let chunk = try pipe.fileHandleForReading.read(upToCount: 8192), !chunk.isEmpty else { break }
                        buffer.append(chunk)
                    } catch { buffer.markReadFailure(); break }
                }
            }
        }
        if let input {
            // Inputs are generated bounded PF rules, never arbitrary scripts.
            DispatchQueue.global(qos: .utility).async {
                try? inPipe.fileHandleForWriting.write(contentsOf: input)
                try? inPipe.fileHandleForWriting.close()
            }
        }
        if ended.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            if ended.wait(timeout: .now() + 0.5) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = ended.wait(timeout: .now() + 1)
            }
            throw HelperFailure("The system command timed out: \(URL(fileURLWithPath: executable).lastPathComponent). Existing firewall rules were not intentionally removed.")
        }
        guard readers.wait(timeout: .now() + 2) == .success else {
            throw HelperFailure("Could not finish reading the system command result.")
        }
        let result = try CommandResult(output: output.result(), error: error.result(), status: process.terminationStatus)
        if requireSuccess && result.status != 0 {
            let detail = (result.error.isEmpty ? result.output : result.error).trimmingCharacters(in: .whitespacesAndNewlines)
            throw HelperFailure("\(URL(fileURLWithPath: executable).lastPathComponent) failed: \(String(detail.prefix(1200)))")
        }
        return result
    }
}
