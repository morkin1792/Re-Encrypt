package reencrypt;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Watches one JSON file and reloads the patterns from it when it changes, so an external process
 * (a script, an agent) can keep Re:Encrypt's configuration up to date while Burp runs.
 *
 * <p>
 * The file is applied on <em>every</em> tick, not only when it changes: it is the source of truth for
 * the patterns it names, so a pattern edited or deleted inside Burp comes back on the next check.
 * Each pattern replaces the configured one with the same name, in place, and anything new is
 * appended; patterns the file does not mention are left alone, so a producer can maintain a couple of
 * entries without owning the user's whole table. Everything it applies is enabled — the point of
 * pointing at a file is that the file runs — so a pattern switched off in the table is switched back
 * on at the next check. A {@code settings} block in an auto-loaded file is ignored; auto-load manages
 * patterns only.
 * </p>
 *
 * <p>
 * Pointing at a path is the trust decision, so patterns land active with no prompt (exchange files
 * carry no {@code enabled} state, and {@code patchProxy} is taken from the file). There is nowhere to
 * show a prompt: this runs off the UI thread.
 * </p>
 */
public class AutoLoader {

    private final Config config;
    private final Consumer<String> log;
    /** Called after a reload so the settings table can show what just landed. */
    private volatile Runnable onReload = () -> {
    };

    private volatile ScheduledExecutorService scheduler;
    private volatile Path watched;
    private volatile long lastCheckMillis;
    private volatile int reloads;
    private volatile String lastError;

    public AutoLoader(Config config, Consumer<String> log) {
        this.config = config;
        this.log = log;
    }

    public void setOnReload(Runnable onReload) {
        this.onReload = onReload == null ? () -> {
        } : onReload;
    }

    /**
     * One line for the settings panel: whether the poll is alive and when it last read the file.
     * Without it there is no way to tell a watcher that is running and seeing no changes from one
     * that stopped.
     */
    public String statusLine() {
        if (scheduler == null || scheduler.isShutdown()) {
            return "Not running.";
        }
        String last = lastCheckMillis == 0 ? "not yet"
                : java.time.LocalTime.ofInstant(java.time.Instant.ofEpochMilli(lastCheckMillis),
                        java.time.ZoneId.systemDefault()).withNano(0).toString();
        return "Watching · last check: " + last + " · reloads: " + reloads
                + (lastError == null ? "" : " · last error: " + lastError);
    }

    public synchronized void start(String path, int intervalSeconds) {
        stop();
        if (path == null || path.isEmpty()) {
            return;
        }
        int seconds = Math.max(1, intervalSeconds);
        watched = resolve(path);
        lastError = null;
        // Say which file, resolved: a path that silently does not exist (a "~" that was never expanded,
        // a relative path against Burp's working directory) is otherwise invisible.
        log.accept("auto-load: watching " + watched.toAbsolutePath() + " every " + seconds + "s");

        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "reencrypt-autoload");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(this::tick, seconds, seconds, TimeUnit.SECONDS);
    }

    public synchronized void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
            log.accept("auto-load: stopped watching " + watched);
        }
    }

    /**
     * Read and apply the given file now, changed or not, and whether or not the watcher is running —
     * this is the "Reload now" button, which doubles as the way to check the path actually works.
     */
    public void reloadNow(String path) {
        if (path != null && !path.isEmpty()) {
            watched = resolve(path);
        }
        if (watched == null) {
            log.accept("auto-load: no file selected");
            return;
        }
        tick();
    }

    /**
     * One poll. Nothing may escape: an exception thrown out of a scheduled task cancels the schedule
     * silently, which looks exactly like "auto-load ran once and then stopped". Throwable, not
     * Exception, because that includes an Error raised while writing to Burp's persistence.
     */
    private void tick() {
        try {
            byte[] content = Files.readAllBytes(watched);
            lastCheckMillis = System.currentTimeMillis();
            reload(new String(content, StandardCharsets.UTF_8));
            lastError = null;
        } catch (Throwable t) {
            String message = t.getClass().getSimpleName() + ": " + t.getMessage();
            if (!message.equals(lastError)) {
                lastError = message;
                log.accept("auto-load failed: " + message);
            }
        }
    }

    private void reload(String content) {
        ConfigJson.ImportResult result = ConfigJson.fromFile(content);
        if (!result.hasPatterns) {
            log.accept("auto-load: file has no \"patterns\" array, ignored");
            return;
        }

        // Auto-loaded patterns are always live: a file that is being watched is meant to be in force,
        // and a pattern that landed disabled would fail silently for as long as nobody noticed.
        for (CapturePattern pattern : result.patterns) {
            pattern.setEnabled(true);
        }
        Config.MergeResult merge = config.mergePatternsByName(result.patterns);
        if (!merge.changed) {
            // Applied, but identical to what was already there: stay silent rather than log and
            // rebuild the table every few seconds while the user is working in it.
            return;
        }

        reloads++;
        String message = "auto-load: " + merge.replaced + " replaced, " + merge.added + " added";
        if (!result.errors.isEmpty()) {
            message += ", " + result.errors.size() + " skipped";
        }
        log.accept(message);
        onReload.run();
    }

    /** Expand a leading {@code ~}, which the shell would have done but Java does not. */
    private static Path resolve(String path) {
        if (path.equals("~") || path.startsWith("~/")) {
            return Paths.get(System.getProperty("user.home"), path.substring(1));
        }
        return Paths.get(path);
    }
}
