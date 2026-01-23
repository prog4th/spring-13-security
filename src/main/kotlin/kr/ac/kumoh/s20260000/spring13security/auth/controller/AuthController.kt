package kr.ac.kumoh.s20260000.spring13security.auth.controller

import jakarta.servlet.http.HttpServletRequest
import kr.ac.kumoh.s20260000.spring13security.auth.service.AuthService
import kr.ac.kumoh.s20260000.spring13security.auth.service.LoginResult
import kr.ac.kumoh.s20260000.spring13security.auth.service.RefreshResult
import kr.ac.kumoh.s20260000.spring13security.global.security.util.JwtUtil.Companion.ACCESS_TOKEN_EXPIRATION_TIME
import kr.ac.kumoh.s20260000.spring13security.global.security.util.JwtUtil.Companion.REFRESH_TOKEN_EXPIRATION_TIME
import kr.ac.kumoh.s20260000.spring13security.user.model.LoginRequest
import kr.ac.kumoh.s20260000.spring13security.user.model.SignupRequest
import kr.ac.kumoh.s20260000.spring13security.user.model.UserResponse
import kr.ac.kumoh.s20260000.spring13security.user.model.toResponse
import kr.ac.kumoh.s20260000.spring13security.user.service.UserService
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import java.time.Duration

@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val authService: AuthService,
    private val userService: UserService,
) {
    companion object {
        private val log = LoggerFactory.getLogger(AuthController::class.java)
    }

    // 회원 가입
    @PostMapping("/signup")
    fun signUp(
        @RequestBody request: SignupRequest
    ): ResponseEntity<UserResponse> {
        log.info(">>> [signUp()] 회원 가입")
        return ResponseEntity
            .ok(userService.signup(request).toResponse())
    }

    // 로그인
    @PostMapping("/login")
    fun login(
        @RequestBody loginRequest: LoginRequest,
    ): ResponseEntity<UserResponse> {
        log.info(">>> [login()] 로그인")

        val result = authService.login(loginRequest)

        return buildLoginResponse(result)
    }

    @PostMapping("/refresh")
    fun refresh(
        request: HttpServletRequest,
    ): ResponseEntity<Unit> {
        log.info(">>> [refresh()] Token 재발급")

        val result = authService.refresh(request)

        return buildRefreshResponse(result)
    }

    // 로그아웃
    @PostMapping("/logout")
    fun logout(): ResponseEntity<Unit> {
        log.info(">>> [logout()] 모든 Cookie 삭제")

        // 만료 시간을 0으로 설정하여 쿠키 삭제를 유도
        val accessTokenCookie = ResponseCookie.from("accessToken", "")
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 true로 변경
            .path("/")
            .maxAge(0) // 삭제
            .build()

        val refreshTokenCookie = ResponseCookie.from("refreshToken", "")
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 true로 변경
            .path("/api/v1/auth/refresh")
            .maxAge(0) // 삭제
            .build()

        return ResponseEntity.noContent() // 204 No Content
            .header(
                HttpHeaders.SET_COOKIE,
                accessTokenCookie.toString()
            )
            .header(
                HttpHeaders.SET_COOKIE,
                refreshTokenCookie.toString()
            )
            .build()
    }

    // 프로필 조회 (Access Token 사용)
    // ADMIN 권한 필요
    @GetMapping("/profile")
    fun getProfile(
        @AuthenticationPrincipal username: String
    ): ResponseEntity<UserResponse> {
        return ResponseEntity
            .ok(userService.getProfile(username).toResponse())
    }

    private fun buildAccessTokenCookie(
        token: String
    ): ResponseCookie =
        ResponseCookie.from("accessToken", token)
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 true로 변경
            .path("/")
            .maxAge(Duration.ofMillis(ACCESS_TOKEN_EXPIRATION_TIME))
            .build()

    private fun buildRefreshTokenCookie(
        token: String
    ): ResponseCookie =
        ResponseCookie.from("refreshToken", token)
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 true로 변경
            .path("/api/v1/auth/refresh")
            .maxAge(Duration.ofMillis(REFRESH_TOKEN_EXPIRATION_TIME))
            .build()

    private fun buildLoginResponse(
        result: LoginResult
    ): ResponseEntity<UserResponse> {

        val accessCookie = buildAccessTokenCookie(result.accessToken)
        val refreshCookie = buildRefreshTokenCookie(result.refreshToken)

        return ResponseEntity.ok()
            .header(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString()
            )
            .header(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString()
            )
            .body(result.userResponse)
    }

    private fun buildRefreshResponse(
        result: RefreshResult
    ): ResponseEntity<Unit> {

        val accessCookie = buildAccessTokenCookie(result.accessToken)
        val refreshCookie = buildRefreshTokenCookie(result.refreshToken)

        return ResponseEntity.noContent() // 204 No Content
            .header(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString()
            )
            .header(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString()
            )
            .build()
    }
}