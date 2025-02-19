import Foundation

public struct Credential: Equatable, Codable {
    public let accessToken: String
    public let sub:String?
    public let tokenType: String
    public let refreshToken: String?
    public let scope: String?
    public let expiresIn: Int?
    public let idToken: String?
    
    enum CodingKeys: String, CodingKey {
        case accessToken
        case sub
        case tokenType
        case refreshToken
        case scope
        case expiresIn, expires
        case idToken
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        scope = try? container.decode(String.self, forKey: .scope)
        idToken = try? container.decode(String.self, forKey: .idToken)
        sub = try? container.decode(String.self,forKey: .sub)
        refreshToken = try? container.decode(String.self, forKey: .refreshToken)

        var expiresIn: Int?
        if let expires = try? container.decode(Int.self, forKey: .expires) {
            expiresIn = expires
        } else if let expires = try? container.decode(Int.self, forKey: .expiresIn) {
            expiresIn = expires
        }
        self.expiresIn = expiresIn
    }

    public init(accessToken:String,sub:String?,tokenType:String,refreshToken:String?,scope:String?,expiresIn:Int?,idToken:String?) {
        self.accessToken = accessToken
        self.sub = sub
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.scope = scope
        self.expiresIn = expiresIn
        self.idToken = idToken
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accessToken, forKey: .accessToken)
        try container.encode(sub, forKey: .sub)
        try container.encode(tokenType, forKey: .tokenType)
        try container.encode(refreshToken, forKey: .refreshToken)
        try? container.encode(scope, forKey: .scope)
        try? container.encode(expiresIn, forKey: .expiresIn)
        try? container.encode(idToken, forKey: .idToken)
    }
}

extension Credential {
    private static let key = "CredentialKey"
    
    public func save() {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = .prettyPrinted
        let data = try? encoder.encode(self)
        UserDefaults.standard.set(data, forKey: Credential.key)
    }
    
    public static func load() -> Credential? {
        guard let credentialsData = UserDefaults.standard.data(forKey: key),
              let credentials = try? JSONDecoder.convertFromSnakeCase.decode(
                Credential.self, from: credentialsData)
        else { return nil }
        return credentials
    }
    
    public static func remove() {
        UserDefaults.standard.setValue(nil, forKey: Credential.key)
    }
}
