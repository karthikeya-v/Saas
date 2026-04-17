import Foundation

enum BlockSource: String, Codable, CaseIterable {
    case phone
    case checkin
    case manual
    case plan
}

struct Block: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var clientId: String = UUID().uuidString
    var startTs: Date
    var endTs: Date
    var source: BlockSource
    var app: String?
    var activity: String?
    var category: String?
    var syncedAt: Date?

    var minutes: Int {
        max(0, Int(endTs.timeIntervalSince(startTs) / 60))
    }
}

extension Block {
    static let categoryColors: [String: String] = [
        "work": "#4f8cff",
        "social": "#ff5c8a",
        "messaging": "#ffb347",
        "email": "#c08cff",
        "browsing": "#9aa5b1",
        "video": "#ff715b",
        "music": "#4cc9f0",
        "audio": "#4cc9f0",
        "learning": "#3ddc97",
        "reading": "#38b000",
        "exercise": "#ef476f",
        "rest": "#8ecae6",
        "sleep": "#264653",
        "meal": "#e9c46a",
        "commute": "#a0a0a0",
        "chores": "#ddbea9",
        "uncategorized": "#cbd5e1",
        "gap": "#e5e7eb"
    ]
}
