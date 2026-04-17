import SwiftUI
import WidgetKit

struct TimeGridWidget: Widget {
    let kind: String = "TimeGridWidget"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: Provider()) { entry in
            TimeGridWidgetView(entry: entry)
        }
        .configurationDisplayName("Today so far")
        .description("Where your minutes went today.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct Entry: TimelineEntry {
    let date: Date
    let accounted: Int
    let total: Int
    let top: String
}

struct Provider: TimelineProvider {
    func placeholder(in context: Context) -> Entry {
        Entry(date: Date(), accounted: 420, total: 600, top: "work")
    }
    func getSnapshot(in context: Context, completion: @escaping (Entry) -> Void) {
        completion(placeholder(in: context))
    }
    func getTimeline(in context: Context, completion: @escaping (Timeline<Entry>) -> Void) {
        let entry = placeholder(in: context)
        let next = Calendar.current.date(byAdding: .minute, value: 15, to: Date())!
        completion(Timeline(entries: [entry], policy: .after(next)))
    }
}

struct TimeGridWidgetView: View {
    var entry: Entry
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Today so far").font(.caption).foregroundStyle(.secondary)
            Text("\(entry.accounted)m")
                .font(.largeTitle.bold().monospacedDigit())
            Text("Top: \(entry.top)").font(.footnote)
        }
        .padding()
    }
}
