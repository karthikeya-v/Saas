import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            NowView()
                .tabItem { Label("Now", systemImage: "clock") }
            TodayView()
                .tabItem { Label("Today", systemImage: "list.bullet.rectangle") }
            PlanView()
                .tabItem { Label("Plan", systemImage: "calendar") }
            ReviewView()
                .tabItem { Label("Review", systemImage: "chart.bar") }
        }
    }
}

#Preview { RootView().environmentObject(BlockStore.shared).environmentObject(SyncEngine.shared) }
