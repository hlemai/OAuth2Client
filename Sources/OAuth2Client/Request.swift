import Foundation
import os.log

extension CharacterSet {
    
    /**
    Return the character set that does NOT need percent-encoding for x-www-form-urlencoded requests INCLUDING SPACE.
    YOU are responsible for replacing spaces " " with the plus sign "+".
    
    RFC3986 and the W3C spec are not entirely consistent, we're using W3C's spec which says:
    http://www.w3.org/TR/html5/forms.html#application/x-www-form-urlencoded-encoding-algorithm
    
    > If the byte is 0x20 (U+0020 SPACE if interpreted as ASCII):
    > - Replace the byte with a single 0x2B byte ("+" (U+002B) character if interpreted as ASCII).
    > If the byte is in the range 0x2A (*), 0x2D (-), 0x2E (.), 0x30 to 0x39 (0-9), 0x41 to 0x5A (A-Z), 0x5F (_),
    > 0x61 to 0x7A (a-z)
    > - Leave byte as-is
    */
    static var wwwFormURLPlusSpaceCharacterSet: CharacterSet {
        var set = CharacterSet().union(CharacterSet.alphanumerics)
        set.insert(charactersIn: "-._* ")
        return set
    }
}

extension String {
    
    fileprivate static var wwwFormURLPlusSpaceCharacterSet: CharacterSet = CharacterSet.wwwFormURLPlusSpaceCharacterSet
    
    /// Encodes a string to become x-www-form-urlencoded; the space is encoded as plus sign (+).
    var wwwFormURLEncodedString: String {
        let characterSet = String.wwwFormURLPlusSpaceCharacterSet
        return (addingPercentEncoding(withAllowedCharacters: characterSet) ?? "").replacingOccurrences(of: " ", with: "+")
    }
    
    /// Decodes a percent-encoded string and converts the plus sign into a space.
    var wwwFormURLDecodedString: String {
        let rep = replacingOccurrences(of: "+", with: " ")
        return rep.removingPercentEncoding ?? rep
    }
}

public struct Request {
    let authorizeURL: String
    let tokenURL: String
    let clientId: String
    let clientSecret:String
    let redirectUri: String
    let specificScheme: String?
    let scopes: [String]
    
    
    public init(
        authorizeURL: String, tokenURL: String, clientId: String,clientSecret: String, redirectUri: String, scopes: [String],specificSheme : String? = nil
    ) {
        self.authorizeURL = authorizeURL
        self.tokenURL = tokenURL
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.redirectUri = redirectUri
        self.scopes = scopes
        self.specificScheme = specificSheme
    }
}

extension Request {
    public func buildAuthorizeURL(pkce: PKCE? = nil) -> URL {
        var queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scopes.joined(separator: "+")),
        ]
        
        if let pkce = pkce {
            queryItems.append(.init(name: "code_challenge", value: pkce.codeChallenge))
            queryItems.append(.init(name: "code_challenge_method", value: pkce.codeChallengeMethod))
        }
        
        var components = URLComponents(string: authorizeURL)!
        components.queryItems = queryItems
        return components.url!
    }
    
    func buildTokenRequest(code:String) -> URLRequest  {
        var request = URLRequest(url: URL(string:tokenURL)! )
        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.addValue("application/json", forHTTPHeaderField: "Accept")

        var bodyValues:  [String: String] = [:]
        bodyValues["redirect_uri"] = self.redirectUri
        bodyValues["grant_type"] = "authorization_code"
        bodyValues["client_id"] = self.clientId
        bodyValues["code"] = code
        bodyValues["client_secret"] = self.clientSecret
        
        
        
        
        var arr: [String] = []
        for (key, val) in bodyValues {
            arr.append("\(key)=\(val.wwwFormURLEncodedString)")
        }
        request.httpBody =  arr.joined(separator: "&").data(using: .utf8, allowLossyConversion: true)
        
        
        return request
    }
    
    
    func buildTokenURL(code: String, pkce: PKCE? = nil) -> URL {
        
        var caracterSet = CharacterSet().union(.alphanumerics)
        caracterSet.insert(charactersIn:"-._*")
        var queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "redirect_uri", value: redirectUri.addingPercentEncoding(withAllowedCharacters: caracterSet )),
            URLQueryItem(name: "client_secret", value: self.clientSecret),
        ]
        
        if let pkce = pkce {
            queryItems.append(.init(name: "code_verifier", value: pkce.codeVerifier))
        }
        
        var components = URLComponents(string: tokenURL)!
        components.queryItems = queryItems
        return components.url!
    }
    
    func buildRefreshTokenURL(refreshToken: String) -> URL {
        let queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "grant_type", value: "refresh_token"),
            URLQueryItem(name: "refresh_token", value: refreshToken),
            URLQueryItem(name: "client_secret", value: self.clientSecret),
        ]
        var components = URLComponents(string: tokenURL)!
        components.queryItems = queryItems
        return components.url!
    }
}
