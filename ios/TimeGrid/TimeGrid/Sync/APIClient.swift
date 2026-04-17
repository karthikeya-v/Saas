import Foundation

struct APIClient {
    var baseURL: URL = Config.apiBase
    var tokenProvider: () -> String? = { TokenStorage.load() }

    func postBlocks(_ blocks: [Block]) async throws -> Int {
        struct Payload: Encodable {
            struct Item: Encodable {
                let client_id: String
                let start_ts: Date
                let end_ts: Date
                let source: String
                let app: String?
                let activity: String?
                let category: String?
            }
            let blocks: [Item]
        }

        let payload = Payload(blocks: blocks.map {
            .init(client_id: $0.clientId,
                  start_ts: $0.startTs,
                  end_ts: $0.endTs,
                  source: $0.source.rawValue,
                  app: $0.app,
                  activity: $0.activity,
                  category: $0.category)
        })

        var request = URLRequest(url: baseURL.appendingPathComponent("v1/blocks"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = tokenProvider() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        request.httpBody = try encoder.encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw NSError(domain: "TimeGrid", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "block upload failed: \(body)"])
        }
        return blocks.count
    }

    func devLogin(appleSub: String, tz: String = TimeZone.current.identifier) async throws -> String {
        var comps = URLComponents(url: baseURL.appendingPathComponent("v1/auth/dev"),
                                  resolvingAgainstBaseURL: false)!
        comps.queryItems = [
            .init(name: "apple_sub", value: appleSub),
            .init(name: "tz", value: tz),
        ]
        var request = URLRequest(url: comps.url!)
        request.httpMethod = "POST"
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw NSError(domain: "TimeGrid", code: -2, userInfo: nil)
        }
        struct Resp: Decodable { let token: String }
        return try JSONDecoder().decode(Resp.self, from: data).token
    }
}
