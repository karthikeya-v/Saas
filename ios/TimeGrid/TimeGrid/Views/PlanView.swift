import SwiftUI

struct PlanView: View {
    @State private var slots: [PlanSlot] = PlanSlot.defaultDay()

    var body: some View {
        NavigationStack {
            List {
                ForEach($slots) { $slot in
                    HStack {
                        Text(slot.label)
                            .font(.body.monospacedDigit())
                            .frame(width: 100, alignment: .leading)
                        TextField("intent", text: $slot.intent)
                            .textFieldStyle(.roundedBorder)
                    }
                }
            }
            .navigationTitle("Plan Tomorrow")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Save") { save() }
                }
            }
        }
    }

    private func save() {
        // TODO: wire to POST /v1/plan via APIClient.
    }
}

struct PlanSlot: Identifiable {
    let id = UUID()
    let start: Int  // hour
    var intent: String = ""
    var label: String { String(format: "%02d:00–%02d:00", start, start + 1) }

    static func defaultDay() -> [PlanSlot] {
        (8...22).map { PlanSlot(start: $0) }
    }
}
