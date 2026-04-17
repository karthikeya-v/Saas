import SwiftUI

struct ReviewView: View {
    @EnvironmentObject private var store: BlockStore

    var body: some View {
        NavigationStack {
            List {
                Section("Today at a glance") {
                    ForEach(summary(), id: \.category) { row in
                        HStack {
                            Circle()
                                .fill(Color(hex: Block.categoryColors[row.category] ?? "#cbd5e1"))
                                .frame(width: 10, height: 10)
                            Text(row.category.capitalized)
                            Spacer()
                            Text("\(row.minutes)m")
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                }
                Section("Open") {
                    Link("View Grafana dashboard",
                         destination: URL(string: "http://localhost:4500")!)
                }
            }
            .navigationTitle("Review")
        }
    }

    private struct Row { let category: String; let minutes: Int }

    private func summary() -> [Row] {
        let blocks = store.blocks(for: Date())
        var bucket: [String: Int] = [:]
        for b in blocks {
            bucket[b.category ?? "uncategorized", default: 0] += b.minutes
        }
        return bucket
            .map { Row(category: $0.key, minutes: $0.value) }
            .sorted { $0.minutes > $1.minutes }
    }
}
