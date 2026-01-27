package kr.ac.kumoh.s20260000.spring13security.global.security.config

import kr.ac.kumoh.s20260000.spring13security.global.filter.LogMdcFilter
import kr.ac.kumoh.s20260000.spring13security.global.security.filter.JwtAuthenticationFilter
import kr.ac.kumoh.s20260000.spring13security.global.security.handler.JwtAccessDeniedHandler
import kr.ac.kumoh.s20260000.spring13security.global.security.handler.JwtAuthenticationEntryPoint
import kr.ac.kumoh.s20260000.spring13security.global.security.util.JwtUtil
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
//@EnableWebSecurity(debug = true)
class SecurityConfig {

    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder()

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.apply {
            // TODO: 배포할 때 Frontend 주소 추가
            allowedOrigins = listOf(
                "http://localhost:5173",
            )
            allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
            allowedHeaders = listOf("*")
            allowCredentials = true // 자격 증명(쿠키 등)을 허용할지 여부
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration) // 모든 경로에 적용
        return source
    }

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        jwtUtil: JwtUtil,
        jwtAuthenticationEntryPoint: JwtAuthenticationEntryPoint,
        jwtAccessDeniedHandler: JwtAccessDeniedHandler,
    ): SecurityFilterChain {
        http {
            csrf { disable() } // JWT 기반 REST API에서는 비활성화. 세션 기반 웹사이트는 필수!

            cors { configurationSource = corsConfigurationSource() } // CORS 설정 적용

            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }

            httpBasic { disable() }
            formLogin { disable() }
            logout { disable() }

            authorizeHttpRequests {
                //authorize( "/api/v1/auth/profile", hasRole("ADMIN")) // permitAll 보다 앞에 나와야 함
                authorize( "/api/v1/auth/profile", authenticated) // permitAll 보다 앞에 나와야 함
                authorize("/api/v1/auth/**", permitAll) // 로그인, 회원가입 경로는 허용
                authorize(anyRequest, authenticated) // 나머지는 인증 필요
            }

            exceptionHandling {
                authenticationEntryPoint = jwtAuthenticationEntryPoint
                accessDeniedHandler = jwtAccessDeniedHandler
            }

            addFilterBefore<UsernamePasswordAuthenticationFilter>(
                LogMdcFilter()
            )
            addFilterBefore<UsernamePasswordAuthenticationFilter>(
                JwtAuthenticationFilter(jwtUtil)
            )
        }

        return http.build()
    }
}