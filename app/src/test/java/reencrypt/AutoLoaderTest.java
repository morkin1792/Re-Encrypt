package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What one auto-load tick does. {@code reloadNow} runs the same code the scheduler runs, on the
 * calling thread, so the behaviour is testable without waiting on a timer.
 */
class AutoLoaderTest {

    private static final String ONE_PATTERN = "{\"reencrypt\":1,\"patterns\":["
            + "{\"name\":\"a\",\"captureRegex\":\"(.*)\"}]}";

    private Config config;
    private AutoLoader autoLoader;
    private final List<String> logged = new ArrayList<>();

    @BeforeEach
    void setUp() {
        config = new Config(FakePersistence.create());
        autoLoader = new AutoLoader(config, logged::add);
    }

    private Path fileWith(Path dir, String content) throws IOException {
        Path file = dir.resolve("patterns.json");
        Files.writeString(file, content);
        return file;
    }

    @Test
    void anAutoLoadedPatternIsAlwaysEnabled(@TempDir Path dir) throws IOException {
        Path file = fileWith(dir, ONE_PATTERN);
        autoLoader.reloadNow(file.toString());
        config.getPatterns().get(0).setEnabled(false); // the user switches it off in the table

        autoLoader.reloadNow(file.toString());

        assertTrue(config.getPatterns().get(0).isEnabled(), "a watched file is meant to be in force");
    }

    @Test
    void aTickThatChangesNothingIsSilent(@TempDir Path dir) throws IOException {
        Path file = fileWith(dir, ONE_PATTERN);
        autoLoader.reloadNow(file.toString());
        logged.clear();

        autoLoader.reloadNow(file.toString());

        assertEquals(List.of(), logged, "an unchanged file must not log or rebuild the table");
    }

    @Test
    void aPatternDeletedInBurpComesBack(@TempDir Path dir) throws IOException {
        Path file = fileWith(dir, ONE_PATTERN);
        autoLoader.reloadNow(file.toString());
        config.removePattern(0);

        autoLoader.reloadNow(file.toString());

        assertEquals(1, config.getPatterns().size());
    }

    @Test
    void aBrokenFileIsReportedAndTheCurrentPatternsSurvive(@TempDir Path dir) throws IOException {
        Path file = fileWith(dir, ONE_PATTERN);
        autoLoader.reloadNow(file.toString());
        Files.writeString(file, "{\"reencrypt\":1,\"patterns\":[{\"nam"); // caught mid-write
        logged.clear();

        autoLoader.reloadNow(file.toString());

        assertEquals(1, config.getPatterns().size());
        assertEquals(1, logged.size());
        assertTrue(logged.get(0).startsWith("auto-load failed:"), logged.get(0));
    }

    @Test
    void aMissingFileIsReportedRatherThanIgnored(@TempDir Path dir) {
        autoLoader.reloadNow(dir.resolve("nope.json").toString());

        assertEquals(1, logged.size());
        assertTrue(logged.get(0).contains("NoSuchFileException"), logged.get(0));
    }
}
