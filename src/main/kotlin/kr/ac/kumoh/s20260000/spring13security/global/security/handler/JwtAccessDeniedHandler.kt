package kr.ac.kumoh.s20260000.spring13security.global.security.handler

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import kr.ac.kumoh.s20260000.spring13security.global.dto.GlobalErrorResponse
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper

@Component
class JwtAccessDeniedHandler(
    private val objectMapper: ObjectMapper
) : AccessDeniedHandler {
    companion object {
        private val log = LoggerFactory.getLogger(JwtAccessDeniedHandler::class.java)
    }

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        log.warn(">>> [Authorization 실패] {} {} : {}",
            request.method,
            request.requestURI,
            accessDeniedException.message
        )

        val errorBody = GlobalErrorResponse(
            message = "해당 리소스에 접근할 권한이 없습니다.",
            code = "INVALID_AUTHORIZATION",
            traceId = MDC.get("traceId")
        )

        response.apply {
            status = HttpServletResponse.SC_FORBIDDEN // 403
            contentType = MediaType.APPLICATION_JSON_VALUE
            characterEncoding = "UTF-8"
            writer.write(objectMapper.writeValueAsString(errorBody))
        }
    }
}