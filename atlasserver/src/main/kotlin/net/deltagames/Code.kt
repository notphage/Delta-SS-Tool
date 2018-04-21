package net.deltagames

import java.util.*

class Code(private var code: IntArray) {
    private var create_time: Long = System.currentTimeMillis()

    fun equals(arr: IntArray): Boolean {
        if (arr.size != code.size)
            return false

        return arr
                .filterIndexed { index, value -> code[index] != value }
                .none()
    }

    fun getCreateTime(): Long {
        return create_time
    }

    override fun toString(): String {
        return Arrays.toString(code)
                .replace(" ", "")
                .replace(",", "")
                .replace("[", "")
                .replace("]", "")
    }
}