package kr.ac.kumoh.s20260000.spring13security.global.filter

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.web.filter.OncePerRequestFilter
import java.util.*

class LogMdcFilter : OncePerRequestFilter() {
    companion object {
        private val log = LoggerFactory.getLogger(LogMdcFilter::class.java)
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain
    ) {
        val traceId = UUID.randomUUID().toString().substring(0, 8)
        MDC.put("traceId", traceId)

        log.info(">>> [START] Request Received")

        try {
            chain.doFilter(request, response)
        } finally {
            log.info(">>> [END] Request Finished")

            // 반드시 clear 해야 함
            MDC.clear()
        }
    }
}
