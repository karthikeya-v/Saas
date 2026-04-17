import SwiftUI

struct NowView: View {
    @EnvironmentObject private var store: BlockStore
    @State private var draft: String = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    headerCard
                    recentChips
                    inputCard
                    Spacer(minLength: 40)
                }
                .padding()
            }
            .navigationTitle("Now")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await NotificationScheduler.fireTest() }
                    } label: { Image(systemName: "bell.badge") }
                }
            }
        }
    }

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("What are you doing?")
                .font(.largeTitle.bold())
            Text(Date(), style: .time)
                .font(.title3)
                .foregroundStyle(.secondary)
        }
    }

    private var recentChips: some View {
        let recents = store.recentActivities()
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack {
                ForEach(recents, id: \.self) { activity in
                    Button {
                        store.logCheckin(activity: activity)
                    } label: {
                        Text(activity)
                            .font(.subheadline)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .opacity(recents.isEmpty ? 0 : 1)
    }

    private var inputCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("e.g. deep work on spec", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .submitLabel(.done)
                .onSubmit(save)
            Button(action: save) {
                Label("Save", systemImage: "arrow.up.circle.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    private func save() {
        let text = draft.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        store.logCheckin(activity: text)
        draft = ""
        focused = false
    }
}
