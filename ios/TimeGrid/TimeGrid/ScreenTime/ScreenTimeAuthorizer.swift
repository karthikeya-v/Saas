import Foundation
#if canImport(FamilyControls)
import FamilyControls
#endif

/// Request FamilyControls (Screen Time) authorization so the app can read
/// DeviceActivity reports. Requires the "Family Controls" capability enabled
/// in Signing & Capabilities.
enum ScreenTimeAuthorizer {
    static func request() async {
        #if canImport(FamilyControls)
        do {
            try await AuthorizationCenter.shared.requestAuthorization(for: .individual)
        } catch {
            print("FamilyControls auth failed: \(error)")
        }
        #else
        // Running in preview / non-device context.
        #endif
    }
}
