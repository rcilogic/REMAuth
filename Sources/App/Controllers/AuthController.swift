//
//  AuthController.swift
//  
//
//  Created by Konstantin Gorshkov on 16.06.2022.
//

import Vapor
import JWT
import Redis
import REMCommons

struct AuthController: RouteCollection {
    typealias User = REMCommons.User
     
    var authSessionTTL: Int { Environment.get(.authSessionTTL).flatMap{ Int($0) } ?? 600 }
    var csrfTokenTTL: Int { Environment.get(.csrfTokenTTL).flatMap{ Int($0) } ?? 60}
    
    func boot(routes: RoutesBuilder) throws {
        let authRoute = routes.grouped ("auth")
        
        authRoute.get("adauth", use: getADAuth)
        authRoute.post("adauth", use: postADAuth)
        
        let securedAuthRoute = authRoute
            .grouped(REMCommons.AuthenticatorBearer())
            .grouped(REMCommons.AuthenticatorSession())
            .grouped(User.guardMiddleware())
            
        securedAuthRoute.get("userinfo", use: getUserInfo)
        securedAuthRoute.post("logout", use: postLogOut)
        
    }
    
    func getUserInfo (req: Request) async throws -> User { try req.auth.require(User.self) }
    
    func postLogOut (req: Request) async throws -> HTTPResponseStatus {
        guard let _ = try? req.auth.require(User.self) else {
            throw Abort(.unauthorized)
        }
        req.session.destroy()
        return .ok
    }
    
    
    func postADAuth (_ req: Request) async throws -> Response {
        let publicKey = try await getAdAuthPublicKey(req: req)
        let adAuthData = try req.content.decode (ADAuthData.self)

        let signers = JWTSigners()
        signers.use(.rs256(key: try RSAKey.public(pem: publicKey)))

        if let token = adAuthData.token {
            var payload = try signers.verify(token, as: ADAuthPayload.self)
            
            guard let csrfAuthToken = req.cookies["__HOST-CSRF_AUTH_TOKEN"]?.string,
                  let _ = try await req.redis.get("csrf:\(csrfAuthToken)", asJSON: Bool.self),
                  csrfAuthToken == payload.requestID else {
                return redirectToErrorPage(error: .badRequest, description: "Invalid CSRF-Auth token")
            }
            
            _ = req.redis.delete("csrf:\(csrfAuthToken)")
            let user = User(name: payload.userName, displayName: payload.displayName, email: payload.email, groups: payload.groups)
            req.session.data[User.key] =  String (data: try JSONEncoder().encode(user), encoding: .utf8)
        }
        return req.redirect(to: "/")
    }
    
    
    func getADAuth (req: Request) async throws -> Response {
        guard let redirectURL = Environment.get(.adAuthURL) else {
            throw Abort(.internalServerError)
        }
        req.session.destroy()
        
        let csrfAuthToken = [UInt8].random(count: 16).base64
        
        let response = Response(
            body: Response.Body(string: makeRedirectPostFormHTML (
                displayText: "Redirecting...",
                values: [
                    "authTarget": Environment.get(.adAuthTargetName) ?? "remauth",
                    "requestID": csrfAuthToken,
                    "groupPrefix": Environment.get(.adAuthGroupPrefix) ?? ""
                ],
                redirectURL: redirectURL
            )))
        
        
        try await req.redis.setex("csrf:\(csrfAuthToken)", toJSON: true, expirationInSeconds: csrfTokenTTL)
        
        response.cookies["__HOST-CSRF_AUTH_TOKEN"] = HTTPCookies.Value (
            string: csrfAuthToken,
            expires: nil,
            maxAge: csrfTokenTTL,
            path: "/",
            isSecure: true,
            isHTTPOnly: true,
            sameSite: HTTPCookies.SameSitePolicy.none)
        
        return response
        
    }
    
    func makeRedirectPostFormHTML (displayText: String = "", values: [String:String], redirectURL: String ) -> String {
        """
        <html>
            <body onload='document.forms["form"].submit()'>
                \(displayText)
                <form name='form' action='\( redirectURL )' method='POST'>
                    \(
                        values.map {key,value in "<input type='hidden' name ='\(key)' value='\(value)'>"}
                        .joined(separator: "\n")
                    )
                </form>
            <body>
        </html>
        """
    }
    
    func redirectToErrorPage (error: HTTPResponseStatus, description: String?) -> Response {
        let body = """
            <html>
                <head>
                    <meta http-equiv = "refresh" content = "0; url = ../error">
                </head>
                <body>
                    Redirecting...
                </body>
            </html>
            """
        let response = Response(body: Response.Body(string: body))
        response.setErrorCookie(error: error, description: description)
        return response
    }
    
    
    func getAdAuthPublicKey (req: Request) async throws -> String {
        guard  let publicKeyURL = Environment.get(.adAuthPublicKey) else {
            throw Abort(.internalServerError)
        }
        let cacheKey = "adAuthPublicKey"
        
        if let result = try await req.cache.get(cacheKey, as: String.self) {
            return result
        } else {
            let response = try await req.client.get("\(publicKeyURL)")
            
            guard
                let body = response.body,
                let publicKey = String(bytes: Data(buffer: body), encoding: .utf8)
            else {
                throw Abort(.internalServerError)
            }
            
            try await req.cache.set(
                cacheKey,
                to: publicKey,
                expiresIn: .seconds(
                    Environment.get(.adAuthPublicKeyTTL).flatMap{ Int($0) } ?? 60
                )
            )
            return publicKey
        }
    }
    
}

    struct ADAuthData: Codable {
        let result: String
        let token: String?
    }

    struct ADAuthPayload: JWTPayload {
        func verify(using signer: JWTSigner) throws {
            try self.expiration.verifyNotExpired()
        }
        
        enum CodingKeys: String, CodingKey {
            case userName = "nameid"
            case displayName = "name"
            case email = "email"
            case groupsString = "groups"
            case issuer = "iss"
            case requestID = "aud"
            case expiration = "exp"
        }
        
        let userName: String
        let displayName: String
        let email: String
        private let groupsString: String
        lazy var groups: [String] = { groupsString.components(separatedBy: ",") }()
        let issuer: String
        let requestID: String
        let expiration: ExpirationClaim
        
    }
