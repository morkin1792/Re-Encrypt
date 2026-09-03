package reencrypt;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;

/**
 * Watches one JSON file and reloads the patterns from it when it changes, so an external process
 * (a script, an agent) can keep Re:Encrypt's configuration up to date while Burp runs.
 *
 * <p>
 * Each pattern in the file replaces the configured one with the same name, in place, and anything new
 * is appended. Patterns the file does not mention are left alone, so a producer can maintain a couple
 * of entries without owning the user's whole table — the flip side is that deleting a pattern from the
 * file does not delete it from Burp. A {@code settings} block in an auto-loaded file is ignored;
 * auto-load manages patterns only.
 * </p>
 *
 * <p>
 * Pointing at a path is the trust decision, so patterns land active with no prompt (exchange files
 * carry no {@code enabled} state, and {@code patchProxy} is taken from the file). There is nowhere to
 * show a prompt: this runs on a background thread.
 * </p>
 */
public class AutoLoader {

    /** A truncate-then-write by the producer must not be read half-finished. */
    private static final long SETTLE_MILLIS = 250;

    private final Config config;
    private final Consumer<String> log;
    /** Called after a reload so the settings table can show what just landed. */
    private volatile Runnable onReload = () -> {
    };
    private Thread thread;
    private volatile boolean running;
    private volatile long lastModified;

    public AutoLoader(Config config, Consumer<String> log) {
        this.config = config;
        this.log = log;
    }

    public void setOnReload(Runnable onReload) {
        this.onReload = onReload == null ? () -> {
        } : onReload;
    }

    public synchronized void start(String path, int intervalSeconds) {
        stop();
        if (path == null || path.isEmpty()) {
            return;
        }
        running = true;
        lastModified = 0;
        thread = new Thread(() -> run(Paths.get(path), Math.max(1, intervalSeconds) * 1000L), "reencrypt-autoload");
        thread.setDaemon(true);
        thread.start();
    }

    public synchronized void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
    }

    private void run(Path path, long intervalMillis) {
        while (running) {
            try {
                Thread.sleep(intervalMillis);
                if (!running) {
                    return;
                }
                if (!Files.exists(path)) {
                    continue;
                }
                long modified = Files.getLastModifiedTime(path).toMillis();
                if (modified == lastModified || System.currentTimeMillis() - modified < SETTLE_MILLIS) {
                    continue;
                }
                lastModified = modified;
                reload(path);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                // Keep the current patterns and keep polling: a half-written file must never leave
                // Burp with an empty or partial set.
                log.accept("auto-load failed: " + e.getMessage());
            }
        }
    }

    private void reload(Path path) throws Exception {
        ConfigJson.ImportResult result = ConfigJson
                .fromFile(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
        if (!result.hasPatterns) {
            log.accept("auto-load: file has no \"patterns\" array, ignored");
            return;
        }

        int replaced = config.mergePatternsByName(result.patterns);

        String message = "auto-load: " + replaced + " replaced, " + (result.patterns.size() - replaced)
                + " added";
        if (!result.errors.isEmpty()) {
            message += ", " + result.errors.size() + " skipped";
        }
        log.accept(message);
        onReload.run();
    }
}
