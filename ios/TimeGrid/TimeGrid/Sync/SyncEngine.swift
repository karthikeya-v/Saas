import Foundation
import SwiftUI

@MainActor
final class SyncEngine: ObservableObject {
    static let shared = SyncEngine()

    @Published var lastSyncAt: Date?
    @Published var lastError: String?

    private let client = APIClient()
    private var timer: Task<Void, Never>?

    func start() async {
        guard timer == nil else { return }
        timer = Task.detached { [weak self] in
            while !Task.isCancelled {
                await self?.syncOnce()
                try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
            }
        }
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    func syncOnce() async {
        let pending = BlockStore.shared.unsynced
        guard !pending.isEmpty else { return }
        do {
            _ = try await client.postBlocks(pending)
            BlockStore.shared.markSynced(clientIds: pending.map(\.clientId))
            lastSyncAt = Date()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }
}
