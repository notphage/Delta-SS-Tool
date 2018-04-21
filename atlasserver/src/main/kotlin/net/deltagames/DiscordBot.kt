package net.deltagames

import net.dv8tion.jda.core.AccountType
import net.dv8tion.jda.core.JDA
import net.dv8tion.jda.core.JDABuilder
import net.dv8tion.jda.core.entities.Game
import net.dv8tion.jda.core.events.message.MessageReceivedEvent
import net.dv8tion.jda.core.hooks.ListenerAdapter

class DiscordBot(private val code_manager: CodeManager) : ListenerAdapter() {
    private var bot: JDA = JDABuilder(AccountType.BOT)
            .setToken("NDE0MzEwMzUyNzA5NDg0NTU1.DWlgHQ.jJWRDHVuwe0JGt3Y0dIBoXI3LBY")
            .addEventListener(this)
            .setGame(Game.of(Game.GameType.DEFAULT, "https://delta.games"))
            .buildBlocking()

    init {
        broadcastMessage("Delta-Bot is currently **online**! Type **!deltahelp** for help.")

        Runtime.getRuntime().addShutdownHook(Thread {
            broadcastMessage("Delta-Bot is currently **offline**!")
        })
    }

    fun broadcastMessage(msg: String, jda: JDA = this.bot) {
        jda.getTextChannelsByName("ss-bot", true).forEach { it.sendMessage(msg).queue() }
    }

    override fun onMessageReceived(event: MessageReceivedEvent) {
        val message = event.message
        val channel = event.textChannel

        if (event.textChannel == null) {
            System.out.println("Received private message by ${message.author.name}. Ignoring it.")
            return
        }

        if (event.textChannel.name != "ss-bot") {
            return
        }

        val msg = message.contentDisplay

        when {
            msg.startsWith("!code") -> {
                System.out.println("Received !code command by ${message.author.name}")

                channel.sendMessage("Your code: ${code_manager.generate_code(channel)}").queue()
            }
            msg.startsWith("!download") -> {
                System.out.println("Received !download command by ${message.author.name}")

                channel.sendMessage("Download link: " + "https://delta.games/delta.exe").queue()
            }
            msg.startsWith("!deltahelp") -> {
                System.out.println("Received !deltahelp command by ${message.author.name}")

                channel.sendMessage("**!code**  - Generates a new code\n" + "**!download**  - Download link for Delta SS Tool").queue()
            }
        }
    }
}