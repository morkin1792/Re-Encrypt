package reencrypt;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ShellCommandTest {

    boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");

    @Test
    void testExecute_Echo_Normal() throws Exception {
        String command = "echo test";
        String expected = "test"; // Echo adds newline, ShellCommand should strip it

        ShellCommand shellCommand = new ShellCommand(command, "");
        CommandOutput output = shellCommand.execute();

        assertEquals(0, output.getExitCode());
        assertEquals(expected, output.getOutput());
    }

    @Test
    void testExecute_Echo_NoNewline() throws Exception {
        if (isWindows)
            return; // Skip on windows as echo behavior is different

        // "echo -n" prevents newline
        String command = "echo -n test";
        String expected = "test";

        ShellCommand shellCommand = new ShellCommand(command, "");
        CommandOutput output = shellCommand.execute();

        assertEquals(0, output.getExitCode());
        assertEquals(expected, output.getOutput());
    }

    @Test
    void testExecute_PreserveWhitespace() throws Exception {
        // Echoing text with spaces
        // We use quotes to ensure shell preserves them in arguments
        String payload = "  spaced  ";
        String command = "echo \"" + payload + "\"";

        // On Linux: echo " spaced " -> | spaced \n|
        // On Windows: echo " spaced " -> |" spaced "\r\n|

        String expected = payload;

        if (isWindows) {
            expected = "\"" + payload + "\"";
        }

        ShellCommand shellCommand = new ShellCommand(command, "");
        CommandOutput output = shellCommand.execute();

        assertEquals(0, output.getExitCode());
        assertEquals(expected, output.getOutput(), "Should preserve leading/trailing spaces");
    }

    @Test
    void testExecute_MultipleNewlines() throws Exception {
        if (isWindows)
            return;

        // printf "line1\nline2\n" -> output has trailing newline
        // ShellCommand should strip only the LAST one.
        // Result: "line1\nline2"
        String command = "printf \"line1\\nline2\\n\"";

        ShellCommand shellCommand = new ShellCommand(command, "");
        CommandOutput output = shellCommand.execute();

        assertEquals("line1\nline2", output.getOutput());
    }

    @Test
    void testExecute_MultipleTrailingNewlines() throws Exception {
        if (isWindows)
            return;

        // printf "test\n\n" -> output has two newlines
        // ShellCommand should strip only ONE.
        // Result: "test\n"
        String command = "printf \"test\\n\\n\"";

        ShellCommand shellCommand = new ShellCommand(command, "");
        CommandOutput output = shellCommand.execute();

        assertEquals("test\n", output.getOutput());
    }
}
