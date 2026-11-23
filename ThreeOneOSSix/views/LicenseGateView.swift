import SwiftUI
import UIKit
import Security

enum LicenseStore {
    private static let key = "argent.license.validated"
    private static let lastCheckKey = "argent.license.lastCheck"
    private static let keychainAccount = "argent.license.key"
    private static let maxSeenKey = "argent.license.maxSeen"
    /// Sin conexión se deja usar la app hasta este tiempo desde la última
    /// verificación correcta; pasado eso se vuelve a pedir internet.
    static let offlineGrace: TimeInterval = 72 * 3600

    /// Solo cuenta como desbloqueada si además hay una licencia guardada que
    /// se pueda volver a verificar (instalaciones viejas la piden otra vez).
    static var isValidated: Bool {
        get { UserDefaults.standard.bool(forKey: key) && savedKey != nil }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }

    static var savedKey: String? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(key value: String) {
        SecItemDelete(baseQuery() as CFDictionary)
        var query = baseQuery()
        query[kSecValueData as String] = Data(value.utf8)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(query as CFDictionary, nil)
        isValidated = true
        markChecked()
    }

    static func markChecked() {
        let now = Date().timeIntervalSince1970
        UserDefaults.standard.set(now, forKey: lastCheckKey)
        UserDefaults.standard.set(max(now, UserDefaults.standard.double(forKey: maxSeenKey)), forKey: maxSeenKey)
    }

    /// Sin internet: ¿ya se acabó el margen? También cuenta como vencido si el
    /// reloj del teléfono se movió hacia atrás (para estirar el margen).
    static var offlineGraceExpired: Bool {
        let now = Date().timeIntervalSince1970
        let defaults = UserDefaults.standard
        let maxSeen = defaults.double(forKey: maxSeenKey)
        let clockWentBack = maxSeen > 0 && now < maxSeen - 300
        defaults.set(max(now, maxSeen), forKey: maxSeenKey)
        let last = defaults.double(forKey: lastCheckKey)
        guard last > 0 else { return true }
        return clockWentBack || now - last > offlineGrace
    }

    /// Quita el desbloqueo y la licencia guardada (venció, la pausaron, etc.).
    static func revoke() {
        UserDefaults.standard.set(false, forKey: key)
        UserDefaults.standard.removeObject(forKey: lastCheckKey)
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "argent.license",
            kSecAttrAccount as String: keychainAccount
        ]
    }
}

struct LicenseGateView: View {
    /// Aviso al volver a la pantalla por una licencia vencida/pausada.
    var initialMessage: String? = nil
    var onUnlocked: () -> Void

    @State private var keyText: String = ""
    @State private var isChecking = false
    @State private var errorMessage: String?

    var body: some View {
        ZStack {
            AppTheme.pageBackground.ignoresSafeArea()

            VStack(spacing: 28) {
                Spacer()

                Image("FoxRankLogo")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 180, height: 180)

                Text("FOXRANK")
                    .font(.system(size: 28, weight: .heavy, design: .default))
                    .foregroundStyle(.white)
                    .tracking(4)

                VStack(spacing: 14) {
                    HStack {
                        Image("FoxRankLogo")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 20, height: 20)
                        SecureField("Ingresa tu licencia", text: $keyText)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                            .foregroundStyle(.white)
                    }
                    .padding()
                    .background(AppTheme.consoleBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))

                    if let errorMessage {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundStyle(AppTheme.accent)
                            .multilineTextAlignment(.center)
                    }

                    Button {
                        validate()
                    } label: {
                        HStack {
                            if isChecking {
                                ProgressView().tint(.white)
                            } else {
                                Text("Desbloquear")
                                    .fontWeight(.bold)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(AppTheme.accent)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    }
                    .disabled(keyText.isEmpty || isChecking)

                    Button {
                        openDiscord()
                    } label: {
                        HStack {
                            Image(systemName: "bubble.left.and.bubble.right.fill")
                            Text("DISCORD")
                                .fontWeight(.bold)
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(AppTheme.consoleBackground)
                        .foregroundStyle(AppTheme.accent)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .strokeBorder(AppTheme.accent.opacity(0.5), lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 32)

                Spacer()
            }
        }
        .onAppear {
            if errorMessage == nil { errorMessage = initialMessage }
        }
    }

    private func openDiscord() {
        guard let url = URL(string: "https://discord.gg/jHbXFA3z8N") else { return }
        UIApplication.shared.open(url)
    }

    private func validate() {
        errorMessage = nil
        isChecking = true
        Task {
            do {
                try await KeyAuthService.license(key: keyText)
                await MainActor.run {
                    isChecking = false
                    LicenseStore.save(key: keyText)
                    onUnlocked()
                }
            } catch {
                await MainActor.run {
                    isChecking = false
                    // TEMP diagnostics: shows the raw KeyAuth error so we can
                    // tell apart a network failure, an API rejection and a
                    // decoding error. Remove once licensing is confirmed working.
                    switch error {
                    case KeyAuthError.network(let detail):
                        errorMessage = "Red: \(detail)"
                    case KeyAuthError.api(let detail):
                        errorMessage = "KeyAuth: \(detail)"
                    case KeyAuthError.decoding:
                        errorMessage = "Respuesta no válida de KeyAuth (decoding)"
                    default:
                        errorMessage = "Error desconocido: \(error)"
                    }
                }
            }
        }
    }
}
