package reencrypt.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import reencrypt.OperationResult;
import reencrypt.ShellCommand;

/**
 * The generated POSIX commands are executed for real: a seeded pattern that does not round-trip
 * is worse than no pattern at all, and these pipelines are exactly the kind of thing that breaks
 * on a padding or line-wrapping detail. Windows commands are only checked for shape -- the
 * PowerShell they wrap cannot be run here.
 */
public class EncodingCommandsTest {

    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    /** Awkward on purpose: '+' and '/' show up in Base64, '=' and '&' break naive quoting. */
    private static final String PLAINTEXT = "user=admin&role=superuser+x/y? ~ end";

    private static String run(String command, String input) throws Exception {
        OperationResult r = new ShellCommand(command, input).execute();
        assertEquals(0, r.getExitCode(), "command failed: " + command + "\n" + r.getOutput());
        return r.getOutput();
    }

    private static void assertRoundTrips(List<String> chain) throws Exception {
        if (IS_WINDOWS) {
            return; // the POSIX pipelines need bash
        }
        String encoded = run(EncodingCommands.encodeCommand(chain, false), PLAINTEXT);
        assertTrue(encoded.indexOf('\n') < 0, "encoded value must stay a single token: " + encoded);
        assertEquals(PLAINTEXT, run(EncodingCommands.decodeCommand(chain, false), encoded),
                "chain " + chain + " did not round-trip");
    }

    @Test
    void base64RoundTrips() throws Exception {
        assertRoundTrips(Arrays.asList("Base64"));
    }

    @Test
    void base64UrlRoundTrips() throws Exception {
        assertRoundTrips(Arrays.asList("Base64URL"));
    }

    @Test
    void hexRoundTrips() throws Exception {
        assertRoundTrips(Arrays.asList("Hex"));
    }

    @Test
    void nestedChainRoundTrips() throws Exception {
        assertRoundTrips(Arrays.asList("Base64", "Base64"));
        assertRoundTrips(Arrays.asList("Base64", "Hex"));
        assertRoundTrips(Arrays.asList("Base64URL", "Base64", "Hex"));
    }

    @Test
    void base64UrlPaddingIsRestoredForEveryLength() throws Exception {
        if (IS_WINDOWS) {
            return;
        }
        List<String> chain = Arrays.asList("Base64URL");
        for (String pt : new String[] { "a", "ab", "abc", "abcd", "abcde" }) {
            String encoded = run(EncodingCommands.encodeCommand(chain, false), pt);
            assertEquals(pt, run(EncodingCommands.decodeCommand(chain, false), encoded),
                    "unpadded Base64URL of length " + pt.length() + " must decode");
        }
    }

    @Test
    void encodeReplaysTheChainBackwards() {
        // Decoding peels Base64 then Hex, so encoding must apply Hex first.
        String dec = EncodingCommands.decodeCommand(Arrays.asList("Base64", "Hex"), false);
        String enc = EncodingCommands.encodeCommand(Arrays.asList("Base64", "Hex"), false);
        assertTrue(dec.indexOf("openssl base64 -d") < dec.indexOf("xxd -r -p"), dec);
        assertTrue(enc.indexOf("xxd -p") < enc.indexOf("openssl base64 -e"), enc);
    }

    /**
     * The Windows commands cannot be executed here, so pin the properties that make them survive
     * the trip through {@code ProcessBuilder} -> {@code cmd.exe /c} -> {@code powershell}. Each is
     * a way the command silently breaks rather than fails loudly.
     */
    @Test
    void windowsCommandsSurviveCmdQuoting() {
        for (String e : new String[] { "Base64", "Base64URL", "Hex" }) {
            for (boolean decode : new boolean[] { true, false }) {
                List<String> chain = Arrays.asList(e);
                String cmd = decode ? EncodingCommands.decodeCommand(chain, true)
                        : EncodingCommands.encodeCommand(chain, true);

                assertTrue(cmd.startsWith("powershell -NoProfile -Command \""), cmd);
                assertTrue(cmd.endsWith("$o.Flush()\""), cmd);

                // Java wraps this argument in quotes without escaping the ones inside it, and
                // cmd /c then strips the first character and the LAST quote. That lands on our
                // own closing quote only while the script adds no double quote of its own.
                assertEquals(2, cmd.chars().filter(c -> c == '"').count(),
                        "exactly one quote pair, else cmd /c strips the wrong one: " + cmd);

                // cmd expands %VAR% inside quotes too.
                assertTrue(cmd.indexOf('%') < 0, "no bare % on a cmd.exe line: " + cmd);

                // Bytes end to end: a trip through .NET strings would be re-encoded by the
                // console code page on the way out.
                assertTrue(cmd.contains("ReadAllBytes('{FILE}')"), cmd);
                assertTrue(cmd.contains("[Console]::OpenStandardOutput()"), cmd);
                assertTrue(cmd.indexOf("::UTF8") < 0, "the payload must not round-trip as UTF-8: " + cmd);
            }
        }
    }

    @Test
    void windowsChainAppliesStagesInTheSameOrderAsPosix() {
        String dec = EncodingCommands.decodeCommand(Arrays.asList("Base64", "Hex"), true);
        String enc = EncodingCommands.encodeCommand(Arrays.asList("Base64", "Hex"), true);
        assertTrue(dec.indexOf("FromBase64String") < dec.indexOf("regex]::Matches"), dec);
        assertTrue(enc.indexOf("BitConverter") < enc.indexOf("ToBase64String"), enc);
    }

    @Test
    void unknownEncodingHasNoCommand() {
        org.junit.jupiter.api.Assertions.assertNull(EncodingCommands.decodeCommand(Arrays.asList("Raw"), false));
        org.junit.jupiter.api.Assertions.assertNull(EncodingCommands.encodeCommand(Arrays.asList("Base64", "Raw"), false));
    }
}
