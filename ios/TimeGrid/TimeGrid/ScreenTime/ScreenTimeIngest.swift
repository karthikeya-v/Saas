import Foundation

/// Bridge between the DeviceActivityReport extension and the app.
/// The report extension writes per-app usage rows into the shared App Group
/// container; the app reads them on launch and in background refresh, and
/// converts them into `Block` records with source=.phone.
///
/// App Group identifier: group.com.timegrid (set in entitlements on both targets).
enum ScreenTimeIngest {
    static let appGroup = "group.com.timegrid"
    static let reportFilename = "screen_time_report.json"

    struct UsageRow: Codable {
        let app: String
        let start: Date
        let end: Date
    }

    static var sharedURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(reportFilename)
    }

    /// Read pending rows written by the report extension and convert to blocks.
    @discardableResult
    static func drainIntoStore() -> Int {
        guard let url = sharedURL, let data = try? Data(contentsOf: url) else { return 0 }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let rows = try? decoder.decode([UsageRow].self, from: data) else { return 0 }

        for r in rows where r.end > r.start {
            let block = Block(
                clientId: "phone-\(r.app)-\(Int(r.start.timeIntervalSince1970))",
                startTs: r.start,
                endTs: r.end,
                source: .phone,
                app: r.app,
                activity: nil,
                category: LocalCategorizer.categorize(app: r.app, activity: nil),
                syncedAt: nil
            )
            Task { @MainActor in BlockStore.shared.add(block) }
        }
        // Truncate once consumed.
        try? Data().write(to: url, options: .atomic)
        return rows.count
    }
}
