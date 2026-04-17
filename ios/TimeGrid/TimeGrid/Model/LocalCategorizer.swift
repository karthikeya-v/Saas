import Foundation

/// Lightweight local categorizer used before a block is synced.
/// The server re-categorizes with the user's custom mappings.
enum LocalCategorizer {
    private static let appKeywords: [(String, String)] = [
        ("instagram", "social"), ("tiktok", "social"), ("twitter", "social"),
        ("facebook", "social"), ("snapchat", "social"),
        ("whatsapp", "messaging"), ("messages", "messaging"), ("telegram", "messaging"),
        ("mail", "email"), ("gmail", "email"), ("outlook", "email"),
        ("safari", "browsing"), ("chrome", "browsing"), ("firefox", "browsing"),
        ("youtube", "video"), ("netflix", "video"),
        ("spotify", "music"), ("podcasts", "audio"),
        ("slack", "work"), ("teams", "work"), ("xcode", "work"),
        ("notion", "work"), ("figma", "work"),
        ("duolingo", "learning"), ("kindle", "reading"), ("books", "reading"),
        ("maps", "commute"), ("uber", "commute"),
        ("strava", "exercise"), ("health", "exercise"),
        ("calm", "rest"), ("headspace", "rest")
    ]

    private static let textKeywords: [String: String] = [
        "sleep": "sleep", "sleeping": "sleep",
        "meeting": "work", "call": "work", "standup": "work",
        "coding": "work", "writing": "work",
        "gym": "exercise", "run": "exercise", "running": "exercise", "walk": "exercise",
        "eat": "meal", "lunch": "meal", "dinner": "meal", "breakfast": "meal",
        "read": "reading", "reading": "reading",
        "cook": "chores", "clean": "chores",
        "commute": "commute", "drive": "commute"
    ]

    static func categorize(app: String?, activity: String?) -> String? {
        if let app = app?.lowercased() {
            for (needle, cat) in appKeywords where app.contains(needle) {
                return cat
            }
        }
        if let activity = activity?.lowercased() {
            for word in activity.split(whereSeparator: { !$0.isLetter }) {
                if let cat = textKeywords[String(word)] { return cat }
            }
        }
        return nil
    }
}
