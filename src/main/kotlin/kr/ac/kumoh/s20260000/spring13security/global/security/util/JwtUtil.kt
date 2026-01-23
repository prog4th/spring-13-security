package kr.ac.kumoh.s20260000.spring13security.global.security.util

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtUtil {
    companion object {
        //const val ACCESS_TOKEN_EXPIRATION_TIME = 60L * 60 * 1000 // 1 시간
        const val ACCESS_TOKEN_EXPIRATION_TIME = 20L * 1000 // 20 초

        //const val REFRESH_TOKEN_EXPIRATION_TIME = 15L * 24 * 60 * 60 * 1000 // 15일
        const val REFRESH_TOKEN_EXPIRATION_TIME = 40L * 1000 // 40 초
    }

    @Value("\${jwt.secret}")
    private lateinit var base64UrlEncodedSecretKey: String

    private val key: SecretKey by lazy  {
        val decodedKey = Base64.getUrlDecoder().decode(base64UrlEncodedSecretKey)
        Keys.hmacShaKeyFor(decodedKey)
    }

    fun generateAccessToken(username: String, role: String): String {
        return Jwts.builder()
            .subject(username)
            .claim("role", role)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun generateRefreshToken(username: String, role: String): String {
        return Jwts.builder()
            .subject(username)
            .claim("role", role)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
        return true
    }

    fun extractUsername(token: String): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload.subject
    }

    fun extractRole(token: String): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload["role"] as? String ?: "ROLE_USER"
    }
}