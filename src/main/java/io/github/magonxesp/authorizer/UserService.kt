package io.github.magonxesp.authorizer

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserService(
    private val userRepository: UserRepository,
) : UserDetailsService {
    override fun loadUserByUsername(username: String?): UserDetails {
        return userRepository.findByEmail(username!!)
            ?: throw UsernameNotFoundException("User $username not found")
    }
}