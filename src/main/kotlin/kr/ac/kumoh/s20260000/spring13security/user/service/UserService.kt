package kr.ac.kumoh.s20260000.spring13security.user.service

import kr.ac.kumoh.s20260000.spring13security.user.model.SignupRequest
import kr.ac.kumoh.s20260000.spring13security.user.model.User
import kr.ac.kumoh.s20260000.spring13security.user.model.UserRole
import kr.ac.kumoh.s20260000.spring13security.user.repository.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
    private val repository: UserRepository,
    private val encoder: PasswordEncoder
) {
    companion object {
        private val log = LoggerFactory.getLogger(UserService::class.java)
    }

    fun signup(request: SignupRequest): User {
        log.info(">>> [회원가입 시도] Username: {}, Nickname: {}", request.username, request.nickname)

        if (repository.existsByUsername(request.username)) {
            log.warn(">>> [회원가입 실패] 중복 아이디 존재: {}", request.username)
            throw IllegalArgumentException("이미 사용 중인 이름입니다.")
        }

        val encodedPassword = encoder.encode(request.password) as String
        log.info("encodedPassword: $encodedPassword")

        val newUser = User(
            username = request.username,
            password = encodedPassword,
            nickname = request.nickname,
            role = if (request.isAdmin)
                UserRole.ROLE_ADMIN
            else
                UserRole.ROLE_USER
        )

        val savedUser = repository.save(newUser)

        log.info(">>> [회원가입 완료] 생성된 사용자 ID: {}, Nickname: {}",
            savedUser.id, savedUser.nickname)

        return savedUser
    }

    fun validateUser(username: String, password: String): User {
        log.info(">>> [사용자 검증 시작] Username: {}", username)

        val user = repository.findByUsername(username)

        if (user == null || !encoder.matches(password, user.password)) {
            log.warn(">>> [사용자 검증 실패] 사용자 이름 또는 비밀번호 불일치: {}", username)
            throw IllegalArgumentException("사용자 이름 또는 비밀번호가 일치하지 않습니다.")
        }

        log.info(">>> [사용자 검증 성공] ID: {}, Role: {}", user.id, user.role)

        return user
    }

    fun getProfile(username: String): User {
        log.info(">>> [프로필 조회 시도] Username: {}", username)

        val user = repository.findByUsername(username)
            ?: run {
                log.warn(">>> [프로필 조회 실패] 사용자 이름이 존재하지 않음: {}", username)
                throw IllegalArgumentException("사용자 이름을 찾을 수 없습니다.")
            }

        log.info(">>> [프로필 조회 성공] User ID: {}, Nickname: {}", user.id, user.nickname)

        return user
    }
}