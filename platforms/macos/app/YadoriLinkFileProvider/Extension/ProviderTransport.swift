import Foundation
import FileProviderCore

/// The Rust core's `yadorilink_fp_provider_call`, blocking up to the core's own timeouts. Callers
/// run on a background queue, never the system's File Provider dispatch queue.
struct FFITransport: ProviderTransport {
    func call(_ request: [String: Any]) -> Data? {
        guard let body = try? JSONSerialization.data(withJSONObject: request),
            let text = String(data: body, encoding: .utf8)
        else { return nil }
        guard let reply = text.withCString({ yadorilink_fp_provider_call($0) }) else { return nil }
        defer { yadorilink_fp_free_string(reply) }
        return String(cString: reply).data(using: .utf8)
    }
}
