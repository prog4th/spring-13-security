package kr.ac.kumoh.s20260000.spring13security.global.dto

import java.time.LocalDateTime

// 공통 에러 응답을 위한 DTO (Data Transfer Object)
data class GlobalErrorResponse(
    val message: String,
    val code: String,
    val traceId: String? = null,
    val timestamp: LocalDateTime = LocalDateTime.now(),
)