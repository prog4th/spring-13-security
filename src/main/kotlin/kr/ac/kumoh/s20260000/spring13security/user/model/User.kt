package kr.ac.kumoh.s20260000.spring13security.user.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document

enum class UserRole {
    ROLE_USER,
    ROLE_ADMIN,
}

@Document(collection = "users")
data class User(
    @Id
    val id: String? = null,

    @Indexed(unique = true)
    val username: String,

    val password: String,
    val nickname: String,
    val role: UserRole = UserRole.ROLE_USER
)

// 확장 함수
fun User.toResponse() = UserResponse(
    id = this.id,
    username = this.username,
    nickname = this.nickname,
    role = this.role
)

data class UserResponse(
    val id: String?,
    val username: String,
    val nickname: String,
    val role: UserRole
)

data class SignupRequest(
    val username: String,
    val password: String,
    val nickname: String,
    val isAdmin: Boolean = false
)

data class LoginRequest(
    val username: String,
    val password: String
)

data class LoginResponse(
    val accessToken: String,
    val refreshToken: String,
    val username: String,
    val role: UserRole,
    val nickname: String
)
