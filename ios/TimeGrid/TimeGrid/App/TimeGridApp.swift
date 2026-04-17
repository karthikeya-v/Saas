import SwiftUI

@main
struct TimeGridApp: App {
    @StateObject private var store = BlockStore.shared
    @StateObject private var sync = SyncEngine.shared

    init() {
        NotificationScheduler.registerCategories()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(sync)
                .task {
                    await NotificationScheduler.requestAuthorizationAndSchedule()
                    await ScreenTimeAuthorizer.request()
                    await sync.start()
                }
        }
    }
}
