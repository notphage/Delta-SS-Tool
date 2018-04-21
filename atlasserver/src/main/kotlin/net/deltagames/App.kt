package net.deltagames

import kotlin.concurrent.fixedRateTimer

class Manager {
    private var code_manager: CodeManager
    private var discord: DiscordBot
    private var server: AuthServer

    init {
        code_manager = CodeManager()
        discord = DiscordBot(code_manager)
        server = AuthServer(code_manager, discord)
    }

    fun tick() {
        code_manager.tick()
    }
}

fun main(args: Array<String>) {
    val manager = Manager()

    fixedRateTimer(name = "tick", period = 200, daemon = true) {
        manager.tick()
    }
}