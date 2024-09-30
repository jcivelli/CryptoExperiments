import java.security.Key
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun encodeBytesToString(bytes : ByteArray) : String {
    return HexFormat.of().formatHex(bytes)
}

fun decodeStringToBytes(string: String) : ByteArray {
    return HexFormat.of().parseHex(string)
}

fun hashToSha256(text : String) : String {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(text.encodeToByteArray())
    return encodeBytesToString(md.digest())
}

fun generateSymmetricKey() : Key {
    val keyGen = KeyGenerator.getInstance("DES")
    keyGen.init(SecureRandom())
    return keyGen.generateKey()
}

fun generateMac(key : Key, message : String) : ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(key)
    return mac.doFinal(message.toByteArray())
}

fun printUsage() {
    println("Usage: crypto_utils <cmd> <params>\n" +
            "Commands:\n" +
            "hash <text>\n\tHash the passed in text with SHA-256\n" +
            "genSymKey\n\tCreates and returns a DES symmetric key, hex encoded.\n" +
            "genHMac <hex encoded key> <message>\n\tReturns a MAC for the given message.\n" +
            "") // TODO: finish with more commands.
}

fun hashCmd(params: List<String>) : String {
    if (params.size != 1) {
        printUsage()
        return ""
    }
    return hashToSha256(params[0])
}

fun genSymKeyCmd(params: List<String>) : String {
    if (params.isNotEmpty()) {
        printUsage()
        return ""
    }
    val key = generateSymmetricKey()
    return encodeBytesToString(key.encoded)
}

fun generateHmacCmd(params: List<String>) : String {
    if (params.size != 2) {
        println("Invalid number of parameters: ${params.size} instead of 2.")
        printUsage()
        return ""
    }
    val keyBytes = decodeStringToBytes(params[0])
    val key = SecretKeySpec(keyBytes, "DES")

    val mac = Mac.getInstance("HmacSHA256")
    mac.init(key)
    val macResult = mac.doFinal(params[1].toByteArray())
    return encodeBytesToString(macResult)
}

fun main(params : Array<String>) {
    if (params.isEmpty()) {
        printUsage()
        return
    }

    val cmd = params[0].lowercase(Locale.getDefault())
    val cmdParams = params.drop(1)
    val result = when (cmd) {
        "hash" -> hashCmd(cmdParams)
        "gensymkey" -> genSymKeyCmd(cmdParams)
        "genhmac" -> generateHmacCmd(cmdParams)
        else -> {
            printUsage()
            ""
        }
    }
    if ("" != result) {
        println(result)
    }
}
