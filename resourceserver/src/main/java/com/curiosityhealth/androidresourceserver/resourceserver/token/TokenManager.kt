package com.curiosityhealth.androidresourceserver.resourceserver.token

import android.content.Context
import com.auth0.jwt.interfaces.DecodedJWT
import com.google.crypto.tink.config.TinkConfig
import com.auth0.jwt.exceptions.JWTCreationException
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.curiosityhealth.androidresourceserver.common.authorization.Authorization
import java.util.*
import com.auth0.jwt.exceptions.JWTVerificationException

interface TokenManager {
    fun generateAccessToken(clientId: String, lifetimeInSeconds: Int = Int.MAX_VALUE) : String?
    fun generateRefreshToken(clientId: String, lifetimeInSeconds: Int = Int.MAX_VALUE) : String?
    fun validateAndDecodeAccessToken(token: String) : DecodedJWT?
    fun validateAndDecodeRefreshToken(token: String) : DecodedJWT?
    fun getClientIdFromToken(token: DecodedJWT) : String?
}

abstract class BaseTokenManager : TokenManager {

    abstract val secret: ByteArray
    abstract val issuer: String
    val verifier: JWTVerifier by lazy {
        val algorithm = Algorithm.HMAC256(this.secret)
        JWT.require(algorithm)
            .withIssuer(this.issuer)
            .build() //Reusable verifier instance
    }

    companion object {
        val CLIENT_ID = "client_id"
        val TOKEN_TYPE = "token_type"
    }

    enum class TokenType {
        ACCESS_TOKEN, REFRESH_TOKEN;

        fun toTokenTypeString(): String {
            when (this) {
                ACCESS_TOKEN -> {
                    return "access"
                }
                REFRESH_TOKEN -> {
                    return "refresh"
                }
            }
        }

        companion object {
            fun fromTokenTypeString(tokenTypeString: String) : TokenType? {
                when (tokenTypeString) {
                    "access" -> { return ACCESS_TOKEN }
                    "refresh" -> { return REFRESH_TOKEN }
                    else -> { return null }
                }
            }
        }
    }

    private fun generateToken(tokenType: TokenType, clientId: String, lifetimeInSeconds: Int): String? {
        try {

            val algorithm = Algorithm.HMAC256(this.secret)

            val now = Date()
            val calendar = Calendar.getInstance()
            calendar.time = now
            calendar.add(Calendar.SECOND, lifetimeInSeconds)
            val expiresAt = calendar.time

            val token = JWT.create()
                .withIssuer(this.issuer)
                .withClaim(CLIENT_ID, clientId)
                .withClaim(TOKEN_TYPE, tokenType.toTokenTypeString())
                .withExpiresAt(expiresAt)
                .sign(algorithm)

            return token

        } catch (exception: JWTCreationException) {
            //Invalid Signing configuration / Couldn't convert Claims.
            return null
        }
    }

    override fun generateAccessToken(clientId: String, lifetimeInSeconds: Int): String? {
        return generateToken(TokenType.ACCESS_TOKEN, clientId, lifetimeInSeconds)
    }

    override fun generateRefreshToken(clientId: String, lifetimeInSeconds: Int): String? {
        return generateToken(TokenType.REFRESH_TOKEN, clientId, lifetimeInSeconds)
    }

    private fun validateAndDecodeToken(token: String, tokenType: TokenType): DecodedJWT? {
        try {
            val jwt = verifier.verify(token)
            //check to see that tokenType is correct
            val encodedTokenType: TokenType? = {
                val tokenTypeClaim = jwt.getClaim(TOKEN_TYPE)
                if (tokenTypeClaim.isNull) null else TokenType.fromTokenTypeString(tokenTypeClaim.asString())
            }()

            if (encodedTokenType != tokenType) {
                return null
            }

            //check to see that it contains a client id
            val clientIdClaim = jwt.getClaim(CLIENT_ID)
            if (clientIdClaim.isNull) {
                return null
            }

            return jwt

        } catch (exception: JWTVerificationException) {
            return null
        }

    }

    override fun validateAndDecodeAccessToken(token: String): DecodedJWT? {
        return this.validateAndDecodeToken(token, TokenType.ACCESS_TOKEN)
    }

    override fun validateAndDecodeRefreshToken(token: String): DecodedJWT? {
        return this.validateAndDecodeToken(token, TokenType.REFRESH_TOKEN)
    }

    override fun getClientIdFromToken(jwt: DecodedJWT): String? {
        val clientIdClaim = jwt.getClaim(CLIENT_ID)
        return if (clientIdClaim.isNull) null else clientIdClaim.asString()
    }
}