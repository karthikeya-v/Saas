import Foundation
import SwiftUI

/// Simple JSON-file-backed store. For v1 this keeps the iOS scaffold focused
/// on UX. Swap in Core Data later without changing the view layer.
@MainActor
final class BlockStore: ObservableObject {
    static let shared = BlockStore()

    @Published private(set) var blocks: [Block] = []

    private let fileURL: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory,
                                           in: .userDomainMask).first!
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("blocks.json")
    }()

    init() { load() }

    func add(_ block: Block) {
        if let idx = blocks.firstIndex(where: { $0.clientId == block.clientId }) {
            blocks[idx] = block
        } else {
            blocks.append(block)
        }
        blocks.sort { $0.startTs < $1.startTs }
        save()
    }

    func logCheckin(activity: String, at end: Date = Date()) {
        let start = lastBoundary(before: end)
        var block = Block(
            clientId: UUID().uuidString,
            startTs: start,
            endTs: end,
            source: .checkin,
            app: nil,
            activity: activity,
            category: nil,
            syncedAt: nil
        )
        block.category = LocalCategorizer.categorize(app: nil, activity: activity)
        add(block)
    }

    func markSynced(clientIds: [String], at date: Date = Date()) {
        var changed = false
        for cid in clientIds {
            if let idx = blocks.firstIndex(where: { $0.clientId == cid }) {
                blocks[idx].syncedAt = date
                changed = true
            }
        }
        if changed { save() }
    }

    var unsynced: [Block] { blocks.filter { $0.syncedAt == nil } }

    func blocks(for day: Date, calendar: Calendar = .current) -> [Block] {
        let start = calendar.startOfDay(for: day)
        let end = calendar.date(byAdding: .day, value: 1, to: start)!
        return blocks.filter { $0.startTs < end && $0.endTs > start }
    }

    func recentActivities(limit: Int = Config.recentActivityCount) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for b in blocks.reversed() {
            guard let a = b.activity, !a.isEmpty, !seen.contains(a) else { continue }
            seen.insert(a)
            out.append(a)
            if out.count >= limit { break }
        }
        return out
    }

    private func lastBoundary(before date: Date) -> Date {
        if let previous = blocks.last?.endTs, previous < date { return previous }
        let cal = Calendar.current
        return cal.date(bySettingHour: cal.component(.hour, from: date) - 1,
                        minute: 0,
                        second: 0,
                        of: date) ?? date.addingTimeInterval(-3600)
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        blocks = (try? decoder.decode([Block].self, from: data)) ?? []
    }

    private func save() {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(blocks) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }
}
