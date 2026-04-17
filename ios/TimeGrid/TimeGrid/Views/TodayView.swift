import SwiftUI

struct TodayView: View {
    @EnvironmentObject private var store: BlockStore

    var body: some View {
        NavigationStack {
            List {
                ForEach(groupedSections, id: \.hour) { section in
                    Section {
                        ForEach(section.blocks) { block in
                            row(block)
                        }
                    } header: {
                        Text("\(section.hour):00")
                            .font(.subheadline.bold())
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Today")
        }
    }

    private struct Section {
        let hour: Int
        let blocks: [Block]
    }

    private var groupedSections: [Section] {
        let blocks = store.blocks(for: Date()).sorted { $0.startTs < $1.startTs }
        var buckets: [Int: [Block]] = [:]
        for b in blocks {
            let h = Calendar.current.component(.hour, from: b.startTs)
            buckets[h, default: []].append(b)
        }
        return buckets.keys.sorted().map { Section(hour: $0, blocks: buckets[$0] ?? []) }
    }

    @ViewBuilder
    private func row(_ block: Block) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(Color(hex: Block.categoryColors[block.category ?? "uncategorized"] ?? "#cbd5e1"))
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 2) {
                Text(block.activity ?? block.app ?? "—")
                    .font(.body)
                HStack(spacing: 4) {
                    Text(block.startTs, style: .time)
                    Text("–")
                    Text(block.endTs, style: .time)
                    if let cat = block.category {
                        Text("· \(cat)")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Text("\(block.minutes)m")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }
}

extension Color {
    init(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") { s.removeFirst() }
        var value: UInt64 = 0
        Scanner(string: s).scanHexInt64(&value)
        let r = Double((value >> 16) & 0xff) / 255
        let g = Double((value >> 8) & 0xff) / 255
        let b = Double(value & 0xff) / 255
        self = Color(red: r, green: g, blue: b)
    }
}
