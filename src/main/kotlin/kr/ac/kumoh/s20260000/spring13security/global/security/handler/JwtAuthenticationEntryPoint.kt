package kr.ac.kumoh.s20260000.spring13security.global.security.handler

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20260000.spring13security.global.dto.GlobalErrorResponse
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper

@Component
class JwtAuthenticationEntryPoint(
    private val objectMapper: ObjectMapper
) : AuthenticationEntryPoint {

    companion object {
        private val log = LoggerFactory.getLogger(JwtAuthenticationEntryPoint::class.java)
    }

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        log.warn(">>> [Authentication 실패] {} {} : {}",
            request.method,
            request.requestURI,
            authException.message
        )

        val errorBody = GlobalErrorResponse(
            message = "인증 정보가 유효하지 않습니다",
            code = "INVALID_AUTHENTICATION",
            traceId = MDC.get("traceId")
        )

        response.apply {
            status = HttpServletResponse.SC_UNAUTHORIZED // 401
            contentType = MediaType.APPLICATION_JSON_VALUE
            characterEncoding = "UTF-8"
            writer.write(objectMapper.writeValueAsString(errorBody))
        }
    }
}