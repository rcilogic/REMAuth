import Vapor
import Redis
import REMCommons

// configures your application
public func configure(_ app: Application) throws {
    // uncomment to serve files from /Public folder
    // app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    app.redis.configuration = try REMCommons.getRedisConfiguration()
    
    app.sessions.use(.redis(delegate: REMRedisSessionsDeligate()))
    app.sessions.configuration.cookieName = REMCommons.sessionCookieName
    app.sessions.configuration.cookieFactory = { sessionID in
            .init(string: sessionID.string,
                  expires: nil,
                  maxAge: Environment.get(.authSessionTTL).flatMap{Int($0)}  ?? 3600,
                  domain: nil,
                  path: "/",
                  isSecure: true,
                  isHTTPOnly: true,
                  sameSite: HTTPCookies.SameSitePolicy.lax)
    }
    
    app.middleware.use(app.sessions.middleware)
    
    Environment.get(.authHTTPHost).flatMap{ app.http.server.configuration.hostname = $0 }
    Environment.get(.authHTTPPort).flatMap{ app.http.server.configuration.port = Int($0) ?? 8080 }
    
    if Environment.get(.adAuthURL) == nil { app.logger.error("AD Auth URL is not set")}
    
    
    // register routes
    try routes(app)
    
}

extension Environment {
    static func get (_ key: REMServiceEnvKey) -> String? { Self.get(key.rawValue) }
    enum REMServiceEnvKey: String {
        case authHTTPHost = "REM_AUTH_HTTP_HOST"
        case authHTTPPort = "REM_AUTH_HTTP_PORT"
        case adAuthTargetName = "REM_AUTH_ADAUTH_TARGETNAME"
        case adAuthPublicKey = "REM_AUTH_ADAUTH_PUBLICKEY_URL"
        case adAuthURL = "REM_AUTH_ADAUTH_URL"
        case adAuthGroupPrefix = "REM_AUTH_ADAUTH_GROUPPREFIX"
        case authSessionTTL = "REM_AUTH_SESSION_TTL"
        case adAuthPublicKeyTTL = "AD_AUTH_PUBLICKEY_TTL"
        case csrfTokenTTL = "REM_AUTH_CSRF_TOKEN_TTL"        
    }
}


struct REMRedisSessionsDeligate: RedisSessionsDelegate {
    
    var expirationInSeconds: Int { Environment.get(.authSessionTTL).flatMap{Int($0)}  ?? 3600 }
    
    func redis<Client>(_ client: Client, store data: SessionData, with key: RedisKey) -> EventLoopFuture<Void> where Client : RedisClient {
        return client.setex(key, toJSON: data, expirationInSeconds: expirationInSeconds)
    }
    
    func redis<Client>(_ client: Client, fetchDataFor key: RedisKey) -> EventLoopFuture<SessionData?> where Client : RedisClient {
        return client.get(key, asJSON: SessionData.self)
    }
        
    public func makeNewID() -> SessionID {
        var bytes = Data()
        for _ in 0..<32 {
            bytes.append(.random(in: .min ..< .max))
        }
        return .init(string: bytes.base64EncodedString())
    }
    
    public func makeRedisKey(for sessionID: SessionID) -> RedisKey {
        return "\(REMCommons.sessionKeyPrefix)\(sessionID.string)"
    }
    
}

