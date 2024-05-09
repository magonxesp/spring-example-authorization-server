package io.github.magonxesp.authorizer

import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Entity
class User(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id: Long? = null,
    var email: String,
    var encodedPassword: String,
) : UserDetails {
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = mutableListOf()
    override fun getPassword(): String = encodedPassword
    override fun getUsername(): String = email
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = true
}