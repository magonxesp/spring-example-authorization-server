package io.github.magonxesp.authorizer;

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.shell.command.annotation.CommandScan

@SpringBootApplication
@CommandScan
class AuthorizerApplication

fun main(args: Array<String>) {
    runApplication<AuthorizerApplication>()
}