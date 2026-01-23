package kr.ac.kumoh.s20260000.spring13security.global.exception

import kr.ac.kumoh.s20260000.spring13security.global.dto.GlobalErrorResponse
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {
    companion object {
        private val log = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)
    }

    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgumentException(
        e: IllegalArgumentException
    ): ResponseEntity<GlobalErrorResponse> {
        log.warn("잘못된 요청 발생: {}", e.message)

        val errorBody = GlobalErrorResponse(
            message = e.message ?: "잘못된 요청입니다.",
            code = "BAD_REQUEST_001",
            traceId = MDC.get("traceId")
        )
        return ResponseEntity
            .badRequest()
            .body(errorBody)
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationException(
        e: MethodArgumentNotValidException
    ): ResponseEntity<GlobalErrorResponse> {
        val errorMessage = e.bindingResult.fieldErrors
            .joinToString(" ") {
                it.defaultMessage ?: "검증 오류"
            }

        log.warn("검증 오류 발생: {}", errorMessage)

        val errorBody = GlobalErrorResponse(
            message = errorMessage,
            code = "VALIDATION_ERROR",
            traceId = MDC.get("traceId")
        )

        return ResponseEntity
            .badRequest()
            .body(errorBody)
    }
}