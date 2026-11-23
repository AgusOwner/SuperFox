import Foundation

enum KeyAuthError: Error {
    case network(String)
    case api(String)
    case decoding
}

enum KeyAuthService {
    private static var sessionId: String?

    /// Identificador estable del dispositivo para cuando "Force HWID" está
    /// activado en el panel de KeyAuth. Se genera una vez y se guarda en
    /// UserDefaults — no cambia entre aperturas de la app.
    private static var hwid: String {
        let storageKey = "argent.keyauth.hwid"
        if let existing = UserDefaults.standard.string(forKey: storageKey) {
            return existing
        }
        let generated = UUID().uuidString
        UserDefaults.standard.set(generated, forKey: storageKey)
        return generated
    }

    private static func post(params: [String: String]) async throws -> [String: Any] {
        guard let url = URL(string: KeyAuthConfig.apiBaseURL) else {
            throw KeyAuthError.network("Invalid API URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let body = params
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
        request.httpBody = body.data(using: .utf8)

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw KeyAuthError.network("URLSession: \(error.localizedDescription)")
        }
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            let bodyPreview = String(data: data.prefix(200), encoding: .utf8) ?? "<non-utf8>"
            throw KeyAuthError.network("HTTP \(code) — \(bodyPreview)")
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            let bodyPreview = String(data: data.prefix(200), encoding: .utf8) ?? "<non-utf8>"
            throw KeyAuthError.network("Decoding failed, raw body: \(bodyPreview)")
        }
        return json
    }

    static func initSession() async throws {
        let params: [String: String] = [
            "type": "init",
            "ver": KeyAuthConfig.version,
            "hash": "",
            "name": KeyAuthConfig.name,
            "ownerid": KeyAuthConfig.ownerid,
            "secret": KeyAuthConfig.secret
        ]
        let json = try await post(params: params)
        guard (json["success"] as? Bool) == true else {
            throw KeyAuthError.api(json["message"] as? String ?? "Init failed")
        }
        sessionId = json["sessionid"] as? String
    }

    static func license(key: String, retrying: Bool = false) async throws {
        if sessionId == nil {
            try await initSession()
        }
        var params: [String: String] = [
            "type": "license",
            "key": key,
            "hwid": hwid,
            "name": KeyAuthConfig.name,
            "ownerid": KeyAuthConfig.ownerid
        ]
        if let sessionId {
            params["sessionid"] = sessionId
        }
        let json = try await post(params: params)
        guard (json["success"] as? Bool) == true else {
            let message = json["message"] as? String ?? "Invalid key"
            // Sesión vencida en el servidor: se abre una nueva y se reintenta una vez.
            if !retrying, message.lowercased().contains("session") {
                sessionId = nil
                try await license(key: key, retrying: true)
                return
            }
            throw KeyAuthError.api(message)
        }
    }

    enum RecheckResult {
        case valid
        case rejected(String)   // KeyAuth la rechazó: vencida, pausada, borrada, baneada…
        case offline            // sin internet / KeyAuth no responde: no se bloquea de inmediato
    }

    /// Vuelve a validar la licencia guardada contra KeyAuth. Se usa al abrir la
    /// app, al volver del fondo y cada pocos minutos con la app abierta.
    static func recheck() async -> RecheckResult {
        guard let key = LicenseStore.savedKey else {
            return .rejected("Ingresa tu licencia de nuevo.")
        }
        do {
            try await license(key: key)
            return .valid
        } catch KeyAuthError.api(let message) {
            return .rejected(friendly(message))
        } catch {
            return .offline
        }
    }

    private static func friendly(_ message: String) -> String {
        let m = message.lowercased()
        if m.contains("expired") { return "Tu licencia venció. Pide una nueva para seguir usando la app." }
        if m.contains("ban") { return "Tu licencia está pausada o bloqueada. Contacta a quien te la dio." }
        if m.contains("not found") || m.contains("invalid") { return "Tu licencia ya no es válida." }
        return message
    }
}
