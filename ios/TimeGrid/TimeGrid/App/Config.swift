import Foundation

enum Config {
    /// Base URL for the TimeGrid backend.
    /// Override with TG_API_BASE in Info.plist for different builds.
    static var apiBase: URL {
        if let override = Bundle.main.object(forInfoDictionaryKey: "TG_API_BASE") as? String,
           let url = URL(string: override) {
            return url
        }
        return URL(string: "http://127.0.0.1:8000")!
    }

    /// Waking hours during which we ping for check-ins.
    static let wakingHours: ClosedRange<Int> = 8...22

    /// How many recent activities to show as one-tap chips on the Now screen.
    static let recentActivityCount = 6

    static let notificationCategory = "TG_CHECKIN"
    static let sameAsLastAction = "TG_SAME_AS_LAST"
    static let openAction = "TG_OPEN"
}
