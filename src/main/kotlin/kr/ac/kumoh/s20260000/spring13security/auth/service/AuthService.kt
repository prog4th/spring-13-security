package kr.ac.kumoh.s20260000.spring13security.auth.service

import jakarta.servlet.http.HttpServletRequest
import kr.ac.kumoh.s20260000.spring13security.global.security.util.JwtUtil
import kr.ac.kumoh.s20260000.spring13security.user.model.LoginRequest
import kr.ac.kumoh.s20260000.spring13security.user.model.UserResponse
import kr.ac.kumoh.s20260000.spring13security.user.model.toResponse
import kr.ac.kumoh.s20260000.spring13security.user.service.UserService
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.stereotype.Service

data class LoginResult(
    val userResponse: UserResponse,
    val accessToken: String,
    val refreshToken: String,
)

data class RefreshResult(
    val accessToken: String,
    val refreshToken: String,
)

@Service
class AuthService(
    private val userService: UserService,
    private val jwt: JwtUtil,
) {
    companion object {
        private val log = LoggerFactory.getLogger(AuthService::class.java)
    }

    fun login(request: LoginRequest): LoginResult {
        log.info(">>> [로그인 시도] {}", request.toString())

        val user = userService.validateUser(request.username, request.password)

        val accessToken = jwt.generateAccessToken(user.username, user.role.toString())
        val refreshToken = jwt.generateRefreshToken(user.username, user.role.toString())

        log.info(">>> [로그인 성공] Username: {}", user.username)

        return LoginResult(
            user.toResponse(),
            accessToken,
            refreshToken,
        )
    }

    fun refresh(request: HttpServletRequest): RefreshResult {
        log.info(">>> [토큰 재발급 시도] {}", request.toString())

        val refreshToken = request.cookies
            ?.find { it.name == "refreshToken" }
            ?.value
            ?: throw AuthenticationCredentialsNotFoundException(
                "Refresh Token이 존재하지 않습니다."
            )

        // NOTE: DB(Redis, MongoDB)에 Refresh Token 저장 고려
        // RTR (Refresh Token Rotation) 보완해 볼 것
        jwt.validateToken(refreshToken)

        val username = jwt.extractUsername(refreshToken)
        val role = jwt.extractRole(refreshToken)

        val newAccessToken =
            jwt.generateAccessToken(username, role)
        val newRefreshToken =
            jwt.generateRefreshToken(username, role)

        log.info(">>> [토큰 재발급 성공]")

        return RefreshResult(
            newAccessToken,
            newRefreshToken,
        )
    }
}