package kr.ac.kumoh.s20260000.spring13security.global.security.filter

import io.jsonwebtoken.ExpiredJwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20260000.spring13security.global.security.util.JwtUtil
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Duration

class JwtAuthenticationFilter(
    private val jwtUtil: JwtUtil,
) : OncePerRequestFilter() {

    companion object {
        private val log = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)
    }

    private val pathMatcher = AntPathMatcher()
    private val excludePath = listOf(
        "/api/v1/auth/signup",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        "/error",
        "/favicon.ico"
    )

    /**
     * Request에 대해 필터 로직([doFilterInternal()])을 실행할지 여부 결정
     * * 회원가입, 로그인, 로그아웃 등 인증이 필요 없는 경로는 'true'를 반환하여
     * JwtAuthenticationFilter를 건너뛰고 바로 다음 필터로 진행
     * - true 반환 시: 인증 정보(SecurityContext)가 비어있는 상태로
     * AuthController의 엔드포인트(/signup, /login)에 도달
     * - false 반환 시: [doFilterInternal()]에서 토큰 검증 및 인증 처리 시도
     *
     * @param request 현재 HTTP 요청 객체
     * @return 필터 실행을 건너뛸 경우 true, 실행할 경우 false
     */
    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val requestURI = request.requestURI

        val exclude = excludePath.any {
            pathMatcher.match(it, requestURI)
        }

        log.info(">>> [shouldNotFilter] {} : {} ({})",
            exclude, requestURI, request.dispatcherType)

        return exclude
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val accessToken = extractToken(request, "accessToken")

        log.info(">>> [doFilterInternal 시작] Access: {}",
            accessToken != null)

        if (accessToken != null) {
            try {
                log.info(">>> [토큰 유효성 검사 시작]")

                jwtUtil.validateToken(accessToken)

                log.info(">>> [토큰 유효성 검사 성공]")

                setAuthenticationContext(request, accessToken)
            } catch (e: Exception) {
                log.info("Access Token 예외 발생: {}", e.message)
                SecurityContextHolder.clearContext()
            }
        }

        log.info(">>> [doFilterInternal() 종료]")
        filterChain.doFilter(request, response)
    }

    private fun extractToken(
        request: HttpServletRequest,
        name: String
    ): String? {
        return request.cookies
            ?.find { it.name == name }
            ?.value
    }

    private fun isValid(token: String?): Boolean {
        if (token == null)
            return false

        return try {
            jwtUtil.validateToken(token)
            true
        } catch (e: ExpiredJwtException) {
            log.info(">>> [isValid()] 토큰 만료 ${e.message}")
            false
        }
    }

    private fun addTokenCookie(
        response: HttpServletResponse,
        name: String,
        token: String,
        duration: Duration
    ) {
        val cookie = ResponseCookie.from(name, token)
            .httpOnly(true)
            .secure(false) // TODO: HTTPS를 사용하고 true로 변경
            .path("/")
            .maxAge(duration)
            .build()

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }

    /**
     * SecurityContextHolder에 Authentication 정보 저장
     * * Controller에서 @AuthenticationPrincipal을 사용하여
     * 현재 로그인한 사용자의 정보를 주입받을 수 있게됨
     *
     * @param request 클라이언트의 요청 객체 (WebAuthenticationDetails 설정용)
     * @param token 검증된 JWT 토큰 (사용자 정보 및 권한 추출용)
     */
    private fun setAuthenticationContext(
        request: HttpServletRequest,
        token: String
    ) {
        log.info(">>>> [setAuthenticationContext()] 시작")

        val username = jwtUtil.extractUsername(token)
        val role = jwtUtil.extractRole(token)
        val authorities = listOf(SimpleGrantedAuthority(role))

        log.info("$username : $authorities")

        // 다음과 같이 @AuthenticationPrincipal 사용해서 얻을 수 있음
        // @GetMapping("/profile")
        //    fun getProfile(@AuthenticationPrincipal username: String)
        //
        // 만약, principal에 UserDetails를 넣었다면 다음과 같이 꺼내야 함
        //    fun getProfile(@AuthenticationPrincipal user: UserDetails)
        val authentication = UsernamePasswordAuthenticationToken(
            username, // principal에 String 타입의 username만 저장함
            null,
            authorities
        )

        authentication.details = WebAuthenticationDetailsSource()
            .buildDetails(request)

        // Spring SecurityContextHolder에 인증 정보 저장
        SecurityContextHolder.getContext()
            .authentication = authentication

        log.info(">>>> [setAuthenticationContext()] 종료")
    }
}