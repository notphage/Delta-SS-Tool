package net.deltagames

import net.dv8tion.jda.core.entities.TextChannel
import java.util.*
import kotlin.collections.ArrayList

class CodeManager {
    private val code_expiration: Int = 1000 * 60 * 5
    private val random_gen = Random()
    private val code_list = ArrayList<Pair<Code, TextChannel>>()

    fun tick() {
        val now = System.currentTimeMillis()

        code_list.forEach {
            if (now - it.first.getCreateTime() > code_expiration) {
                println("Code ${it.first} expired!")

                code_list.remove(it)
            }
        }
    }

    fun generate_code(channel: TextChannel): String {
        fun rand_int(): Int {
            return random_gen.nextInt(9)
        }

        val code: IntArray = intArrayOf(rand_int(), rand_int(), rand_int(), rand_int(), rand_int(), rand_int(), rand_int(), rand_int())

        code_list.add(Pair(Code(code), channel))

        val code_string = Arrays.toString(code)
                .replace(" ", "")
                .replace(",", "")
                .replace("[", "")
                .replace("]", "")

        println("Generated code $code_string")

        return code_string
    }

    fun use_code(str: String): Boolean {
        if (str.length != 8)
            return false

        str.forEach { if (!it.isDigit()) return false }

        val int_arr = IntArray(8)

        for ((index, value) in str.withIndex()) int_arr[index] = (value - '0')

        return use_code(int_arr)
    }

    fun use_code(arr: IntArray): Boolean {
        if (arr.size != 8)
            return false

        code_list.forEach {
            if (it.first.equals(arr)) {
                println("Code $it was used!")
                it.second.sendMessage("${it.first} was used.").queue()

                code_list.remove(it)

                return true
            }
        }

        return false
    }
}