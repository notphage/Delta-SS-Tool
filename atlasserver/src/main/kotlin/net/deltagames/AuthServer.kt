package net.deltagames

import spark.Spark.*
import java.util.Base64
import java.util.concurrent.ThreadLocalRandom
import kotlin.collections.ArrayList
import kotlin.collections.forEach
import kotlin.collections.indices
import kotlin.collections.toMutableList
import kotlin.experimental.xor

class AuthServer(private val code_manager: CodeManager, private val discord: DiscordBot) {
    private val versions = StringList("/home/ec2-user/strings/versions")
    private val process = StringList("/home/ec2-user/strings/process")
    private var servers = StringList("/home/ec2-user/strings/servers", true)
    private var javaw = StringList("/home/ec2-user/strings/javaw")
    private var explorer = StringList("/home/ec2-user/strings/explorer")

    init {
        port(8880)
        threadPool(10, 5, 1000)

        path("/ss") {
            get("") { request, _ ->
                if (request.queryParams("code") != null) {
                    return@get handle_ss(request.queryParams("code"), request.ip())
                }
                ""
            }
        }

        path("/ac") {
            get("") { request, _ ->
                if (request.queryParams("hwid") != null) {
                    return@get handle_ac(request.queryParams("hwid"), request.ip())
                }
                ""
            }
        }
    }

    private fun handle_ss(code: String, ip: String): String {
        println("[SS] Client $ip has connected.")

        var rtn = ""

        if (code_manager.use_code(code)) {
            println("[SS] Client $ip used a valid code. Sending strings...")

            val str = StringBuilder()
            str.append("[15405021277798861866]$explorer[8196834748168278412]$versions[133628619820746138]$process[12053029889638126454]$javaw")

            rtn = str.toString()
            rtn = encode(rtn, code)

            println("[SS} Done handling $ip")
        } else {
            println("[SS] Client $ip used an invalid code.")
        }

        println("[SS] Client $ip was disconnected.")

        return rtn
    }

    fun encode(s: String, key: String): String {
        return base64Encode(xorWithKey(s.toByteArray(), key.toByteArray()))
    }

    private fun xorWithKey(a: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(a.size)
        for (i in a.indices) {
            out[i] = (a[i].xor(key[i % key.size]))
        }
        return out
    }

    private fun base64Encode(bytes: ByteArray): String {
        return Base64.getEncoder().encodeToString(bytes).toString()
    }

    private fun shuffle(input: String): String {
        val characters = input.toCharArray().toMutableList()
        val output = StringBuilder(input.length)
        while (characters.size != 0) {
            val randPicker = (Math.random() * characters.size).toInt()
            output.append(characters.removeAt(randPicker))
        }
        return output.toString()
    }

    private fun generate_hash(valid: Boolean, ip: String): String {
        println("[AC] Client $ip has connected.")

        val misc_chars = "0123456789"
        val cap_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val lower_chars = "abcdefghijklmnopqrstuvwxyz"

        val str = StringBuilder()

        val num_misc: Int
        val num_cap: Int
        val num_lower: Int

        if (valid) {
            println("[AC] Client $ip was authed.")

            num_misc = ThreadLocalRandom.current().nextInt(14, 20)
            num_cap = ThreadLocalRandom.current().nextInt(20, 28)
            num_lower = num_cap + ThreadLocalRandom.current().nextInt(5, 10)
        } else {
            println("[AC] Client $ip was rejected.")

            num_misc = ThreadLocalRandom.current().nextInt(18, 24)
            num_cap = ThreadLocalRandom.current().nextInt(15, 22)
            num_lower = num_cap - ThreadLocalRandom.current().nextInt(4, 6)
        }

        for (i in num_misc downTo 0) {
            str.append(misc_chars[ThreadLocalRandom.current().nextInt(0, misc_chars.length)])
        }

        for (i in num_cap downTo 0) {
            str.append(cap_chars[ThreadLocalRandom.current().nextInt(0, cap_chars.length)])
        }

        for (i in num_lower downTo 0) {
            str.append(lower_chars[ThreadLocalRandom.current().nextInt(0, lower_chars.length)])
        }

        println("[AC] Client $ip was disconnected.")

        return shuffle(str.toString())
    }

    private fun handle_ac(hwid: String, ip: String): String {
        return generate_hash(servers.contains(hwid), ip)
    }
}