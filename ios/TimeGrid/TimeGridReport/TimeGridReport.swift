import Foundation
#if canImport(DeviceActivity)
import DeviceActivity
import SwiftUI

/// DeviceActivityReport extension. Extensions run in a sandbox; use the
/// shared App Group container to hand aggregated usage back to the app.
@main
struct TimeGridReportExtension: DeviceActivityReportExtension {
    var body: some DeviceActivityReportScene {
        TimeGridUsageScene()
    }
}

struct TimeGridUsageScene: DeviceActivityReportScene {
    let context: DeviceActivityReport.Context = .init(rawValue: "Daily")
    let content: (DeviceActivityResults<DeviceActivityData>) -> TimeGridUsageView = {
        TimeGridUsageView(data: $0)
    }

    func makeConfiguration(representing data: DeviceActivityResults<DeviceActivityData>) async
        -> DeviceActivityResults<DeviceActivityData> {
        await UsageExporter.export(results: data)
        return data
    }
}

struct TimeGridUsageView: View {
    let data: DeviceActivityResults<DeviceActivityData>
    var body: some View { Text("TimeGrid report") }
}

enum UsageExporter {
    static func export(results: DeviceActivityResults<DeviceActivityData>) async {
        guard let groupURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.timegrid") else { return }
        let outURL = groupURL.appendingPathComponent("screen_time_report.json")

        struct Row: Codable {
            let app: String
            let start: Date
            let end: Date
        }
        var rows: [Row] = []

        for await activitySegment in results {
            for await categoryActivity in activitySegment.activitySegments {
                let interval = categoryActivity.dateInterval
                for await appActivity in categoryActivity.categories {
                    for await app in appActivity.applications {
                        rows.append(Row(
                            app: app.application.localizedDisplayName ?? "unknown",
                            start: interval.start,
                            end: interval.end
                        ))
                    }
                }
            }
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(rows) {
            try? data.write(to: outURL, options: .atomic)
        }
    }
}
#endif
