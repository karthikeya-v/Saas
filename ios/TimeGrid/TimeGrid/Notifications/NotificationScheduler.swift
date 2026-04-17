import Foundation
import UserNotifications

enum NotificationScheduler {
    static func registerCategories() {
        let sameAsLast = UNNotificationAction(
            identifier: Config.sameAsLastAction,
            title: "Same as last",
            options: []
        )
        let open = UNNotificationAction(
            identifier: Config.openAction,
            title: "Log now",
            options: [.foreground]
        )
        let category = UNNotificationCategory(
            identifier: Config.notificationCategory,
            actions: [sameAsLast, open],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    static func requestAuthorizationAndSchedule() async {
        let center = UNUserNotificationCenter.current()
        do {
            let granted = try await center.requestAuthorization(
                options: [.alert, .sound, .badge]
            )
            guard granted else { return }
            await rescheduleAll()
        } catch {
            print("notification auth failed: \(error)")
        }
    }

    /// Schedule a repeating notification at minute 0 of every waking hour.
    /// iOS allows up to 64 pending requests; one per hour for 15 hours/day is fine.
    static func rescheduleAll() async {
        let center = UNUserNotificationCenter.current()
        let pending = await center.pendingNotificationRequests()
        let ourIds = pending.filter { $0.identifier.hasPrefix("tg.checkin.") }.map(\.identifier)
        center.removePendingNotificationRequests(withIdentifiers: ourIds)

        for hour in Config.wakingHours {
            var comps = DateComponents()
            comps.hour = hour
            comps.minute = 0
            let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: true)

            let content = UNMutableNotificationContent()
            content.title = "What are you doing?"
            content.body = "Log the last hour in 5 seconds."
            content.sound = .default
            content.categoryIdentifier = Config.notificationCategory
            content.userInfo = ["hour": hour]

            let request = UNNotificationRequest(
                identifier: "tg.checkin.\(hour)",
                content: content,
                trigger: trigger
            )
            try? await center.add(request)
        }
    }

    static func fireTest() async {
        let content = UNMutableNotificationContent()
        content.title = "What are you doing?"
        content.body = "Test ping"
        content.sound = .default
        content.categoryIdentifier = Config.notificationCategory
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 5, repeats: false)
        try? await UNUserNotificationCenter.current().add(
            UNNotificationRequest(
                identifier: "tg.checkin.test",
                content: content,
                trigger: trigger
            )
        )
    }
}
