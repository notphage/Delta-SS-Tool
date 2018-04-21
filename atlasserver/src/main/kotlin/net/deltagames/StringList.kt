package net.deltagames

import java.io.File

class StringList(file: String, server: Boolean = false) {
    private var str_list = ArrayList<String>()
    private val rtn_str = StringBuilder()

    init {
        println("Loading strings from $file...")

        File(file).walk().forEach {
            if (it.isFile)
            {
                if (server)
                {
                    str_list.addAll(it.readLines())
                }
                else
                {
                    val lines = it.readLines()
                    if (!lines.isEmpty())
                    {
                        rtn_str.append("{ ${lines[0]}")

                        it.readLines()
                                .asSequence()
                                .mapNotNull { Regex("([0-9A-Fa-f]{2}[ ])+([0-9A-Fa-f]{2})").find(it) }
                                .forEach {  rtn_str.append("(" + it.value + ") ") }

                        rtn_str.append(" }")
                    }
                }
            }
        }
    }

    fun contains(str: String): Boolean {
        return str_list.contains(str)
    }

    override fun toString(): String {
        return rtn_str.toString()
    }
}