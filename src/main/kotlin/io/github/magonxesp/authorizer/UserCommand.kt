package io.github.magonxesp.authorizer

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.shell.command.annotation.Command
import org.springframework.shell.command.annotation.Option

@Command(command = ["user"])
class UserCommand(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) {
    @Command(command = ["create"])
    fun create(
        @Option(required = true) email: String,
        @Option(required = true) password: String,
    ) {
        val user = User(
            email = email,
            encodedPassword = passwordEncoder.encode(password)
        )

        userRepository.save(user)
    }
}