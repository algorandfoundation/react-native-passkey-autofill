package co.algorand.passkeyautofill.utils

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Static check standing in for a lint rule: every log line in the module must
 * go through [PasskeyLog], so release stripping and the no-payload rule cannot
 * be bypassed by a stray `android.util.Log` call in a security-relevant file.
 */
class LoggingPolicyTest {
    private val rawLogImport = Regex("""^\s*import\s+android\.util\.Log\s*$""", RegexOption.MULTILINE)
    private val rawLogCall = Regex("""(^|[^A-Za-z])Log\.(d|i|w|e|v|wtf)\(""")

    /** `src/main/java` of this module, whatever directory Gradle runs the tests from. */
    private fun mainSources(): File {
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "src/main/java/co/algorand/passkeyautofill")
            if (candidate.isDirectory) return candidate
            dir = dir.parentFile
        }
        throw AssertionError("Could not locate the module's src/main/java from ${File("").absolutePath}")
    }

    @Test
    fun onlyPasskeyLogTouchesAndroidUtilLog() {
        val offenders = mainSources().walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "PasskeyLog.kt" }
            .filter { file ->
                val source = file.readText()
                rawLogImport.containsMatchIn(source) || rawLogCall.containsMatchIn(source)
            }
            .map { it.name }
            .toList()
        assertEquals("Route logging through PasskeyLog in: $offenders", emptyList<String>(), offenders)
    }

    @Test
    fun theLoggerItselfIsTheOnlyPlaceThatImportsIt() {
        val logger = File(mainSources(), "utils/PasskeyLog.kt")
        assertTrue(logger.isFile)
        assertTrue(rawLogImport.containsMatchIn(logger.readText()))
    }
}
