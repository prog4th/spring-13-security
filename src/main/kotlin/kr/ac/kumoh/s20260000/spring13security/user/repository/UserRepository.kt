package kr.ac.kumoh.s20260000.spring13security.user.repository

import kr.ac.kumoh.s20260000.spring13security.user.model.User
import org.springframework.data.mongodb.repository.MongoRepository

interface UserRepository : MongoRepository<User, String> {
    fun existsByUsername(username: String): Boolean
    fun findByUsername(username: String): User?
}