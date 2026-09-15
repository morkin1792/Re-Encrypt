package reencrypt;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reencrypt.engine.CryptoEngine;
import reencrypt.engine.CryptoEngineRegistry;
import reencrypt.engine.CryptoException;
import reencrypt.exception.CommandException;
import reencrypt.exception.PatternException;

public class ReEncrypt {
    Config config;

    public ReEncrypt(Config config) {
        this.config = config;
    }

    public Config getConfig() {
        return config;
    }

    public byte[] encryptAndPatch(byte[] request, CapturePattern pattern, String plainText, LogData logData)
            throws Exception {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = encrypt(pattern, plainText);
        if (pattern.shouldSaveToLog()) {
            logData.update(cipherText, plainText, pattern.getName(), "Encrypt");
            config.writeLog(logData);
        }
        return patchRequest(request, beginIndex, endIndex, cipherText.getBytes());
    }

    public byte[] matchReplace(byte[] request, CapturePattern pattern, String newValue) throws PatternException {
        return matchReplace(request, pattern, newValue, null);
    }

    /**
     * Replace the captured span with {@code newValue}. When {@code outSpan} is a length-3 array
     * it is filled with {newStart, newEnd, oldEnd}: the byte range the new value occupies in the
     * returned content, plus the end of the region that was replaced (so callers can adjust other
     * tracked spans by the length delta). This lets the print editor highlight exactly the
     * decrypted regions instead of re-matching the regex (which can hit false positives).
     */
    public byte[] matchReplace(byte[] request, CapturePattern pattern, String newValue, int[] outSpan)
            throws PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        byte[] newBytes = newValue.getBytes();
        if (outSpan != null && outSpan.length >= 3) {
            outSpan[0] = beginIndex;
            outSpan[1] = beginIndex + newBytes.length;
            outSpan[2] = endIndex;
        }
        return patchRequest(request, beginIndex, endIndex, newBytes);
    }

    public String encrypt(CapturePattern pattern, String plainText) throws Exception {
        if (pattern.usesEngine()) {
            CryptoEngine engine = CryptoEngineRegistry.get(pattern.getEngineId());
            return engine.encrypt(plainText, pattern.getEngineParams());
        }
        ShellCommand command = new ShellCommand(pattern.getEncCommand(), plainText);
        return command.execute().getOutputCheckingExitCode();
    }

    public String encrypt(String rawCommand, String plainText)
            throws IOException, InterruptedException, CommandException {
        ShellCommand command = new ShellCommand(rawCommand, plainText);
        String cipherText = command.execute().getOutputCheckingExitCode();
        return cipherText;
    }

    /** One planned replacement: a byte range of the ORIGINAL content, and what belongs there. */
    public static final class Replacement {
        public final int start;
        public final int end;
        public final byte[] value;

        public Replacement(int start, int end, byte[] value) {
            this.start = start;
            this.end = end;
            this.value = value;
        }
    }

    /**
     * The range this pattern would replace, measured against {@code content}, widened over the
     * wrapping quotes when {@link #matchReplaceUnquoting} would absorb them.
     *
     * @return {@code {start, end}}
     */
    public static int[] replacementSpan(byte[] content, CapturePattern pattern, String newValue)
            throws PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), content);
        int begin = indexes[0];
        int end = indexes[1];
        if (begin > 0 && end < content.length && content[begin - 1] == '"' && content[end] == '"'
                && looksLikeJson(newValue)) {
            begin--;
            end++;
        }
        return new int[] { begin, end };
    }

    /**
     * Apply replacements that were all measured against the same original content, in a single pass.
     *
     * <p>
     * Replacing them one at a time is what corrupted the Print Tab: the second pattern's regex ran over
     * text the first had already substituted, matched a quote inside it and spliced the payload in
     * again. Every span here refers to the untouched content, so no pattern can ever see another's
     * output.
     * </p>
     *
     * <p>
     * Two patterns claiming overlapping bytes cannot both win; the earlier span is applied and the
     * other skipped. That case is already reported to the user as an overlap warning.
     * </p>
     *
     * @param outSpans receives where each applied replacement landed in the returned bytes
     */
    public static byte[] applyReplacements(byte[] content, java.util.List<Replacement> replacements,
            java.util.List<int[]> outSpans) {
        java.util.List<Replacement> ordered = new java.util.ArrayList<>(replacements);
        ordered.sort(java.util.Comparator.comparingInt(r -> r.start));

        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(content.length);
        int cursor = 0;
        for (Replacement r : ordered) {
            if (r.start < cursor || r.start > content.length || r.end > content.length) {
                continue; // overlaps one already applied, or out of range
            }
            out.write(content, cursor, r.start - cursor);
            int landedAt = out.size();
            out.write(r.value, 0, r.value.length);
            if (outSpans != null) {
                outSpans.add(new int[] { landedAt, out.size() });
            }
            cursor = r.end;
        }
        out.write(content, cursor, content.length - cursor);
        return out.toByteArray();
    }

    /**
     * Print-view replacement that can absorb the quotes around the captured value.
     *
     * <p>
     * A JSON-param pattern captures the blob <em>inside</em> the quotes, so splicing JSON plaintext
     * there yields {@code {"data":"{"a":1}"}} - unescaped quotes inside a string, which is not JSON, so
     * Burp's Pretty tab has nothing it can format. Taking the surrounding quotes with it yields
     * {@code {"data":{"a":1}}}, a real nested object that Pretty renders properly.
     * </p>
     *
     * <p>
     * Only when the value really is bracketed by quotes and the plaintext really parses as JSON;
     * anything else falls through to the plain replacement, so non-JSON payloads are untouched.
     * </p>
     */
    public byte[] matchReplaceUnquoting(byte[] content, CapturePattern pattern, String newValue, int[] outSpan)
            throws PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), content);
        int begin = indexes[0];
        int end = indexes[1];
        if (begin > 0 && end < content.length && content[begin - 1] == '"' && content[end] == '"'
                && looksLikeJson(newValue)) {
            begin--;
            end++;
        }
        byte[] newBytes = newValue.getBytes();
        if (outSpan != null && outSpan.length >= 3) {
            outSpan[0] = begin;
            outSpan[1] = begin + newBytes.length;
            outSpan[2] = end;
        }
        return patchRequest(content, begin, end, newBytes);
    }

    /** A full parse, not a bracket check: turning valid output into a broken document would be worse. */
    static boolean looksLikeJson(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || (trimmed.charAt(0) != '{' && trimmed.charAt(0) != '[')) {
            return false;
        }
        try {
            com.google.gson.JsonParser.parseString(trimmed);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Rewrite Content-Length so it matches the body actually present.
     *
     * <p>
     * Replacing ciphertext with plaintext changes the body's length, and the editor path - unlike the
     * proxy and Intruder handlers - never corrected the header, so Burp was handed a message whose
     * declared length disagreed with its body and would not parse it.
     * </p>
     *
     * @param outShift receives {@code {offsetWhereBytesChanged, delta}} so callers can move any byte
     *                 offsets they hold (the Print Tab's highlight spans) across the edit
     * @return the message with a correct Content-Length, or the original when it has no such header
     */
    public static byte[] fixContentLength(byte[] message, int[] outShift) {
        if (outShift != null && outShift.length >= 2) {
            outShift[0] = 0;
            outShift[1] = 0;
        }
        String text = new String(message, java.nio.charset.StandardCharsets.ISO_8859_1);
        int headerEnd = text.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            return message;
        }
        int bodyLength = message.length - (headerEnd + 4);
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(?im)^content-length:[ \\t]*(\\d+)[ \\t]*$", java.util.regex.Pattern.MULTILINE)
                .matcher(text.substring(0, headerEnd));
        if (!m.find()) {
            return message;
        }
        String correct = Integer.toString(bodyLength);
        if (correct.equals(m.group(1))) {
            return message;
        }
        int valueStart = m.start(1);
        int valueEnd = m.end(1);
        byte[] digits = correct.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        if (outShift != null && outShift.length >= 2) {
            outShift[0] = valueEnd;
            outShift[1] = digits.length - (valueEnd - valueStart);
        }
        byte[] out = new byte[message.length + digits.length - (valueEnd - valueStart)];
        System.arraycopy(message, 0, out, 0, valueStart);
        System.arraycopy(digits, 0, out, valueStart, digits.length);
        System.arraycopy(message, valueEnd, out, valueStart + digits.length, message.length - valueEnd);
        return out;
    }

    byte[] patchRequest(byte[] rawContent, int beginIndex, int endIndex, byte[] contentPayload) {
        byte[] preContent = Arrays.copyOfRange(rawContent, 0, beginIndex);
        byte[] postContent = Arrays.copyOfRange(rawContent, endIndex, rawContent.length);

        byte[] newRequest = new byte[preContent.length + contentPayload.length + postContent.length];
        System.arraycopy(preContent, 0, newRequest, 0, preContent.length);
        System.arraycopy(contentPayload, 0, newRequest, preContent.length, contentPayload.length);
        System.arraycopy(postContent, 0, newRequest, preContent.length + contentPayload.length, postContent.length);
        return newRequest;
    }

    /**
     * A capture regex slower than this is a problem, not a slow machine: it runs several times per
     * message, on every tool, so a badly shaped one (an unanchored {@code [A-Za-z0-9+/=]{20,}} over a
     * long base64 header backtracks quadratically) freezes the editor with no clue as to why.
     */
    public static final long SLOW_MATCH_MILLIS = 750;
    /**
     * Regexes seen to be slow at least once. Sticky on purpose: a regex is matched several times per
     * message, and every run after the first is warm, so timing the run that happens to reach the UI
     * would report a fraction of the delay the user actually waited on. It also keeps the warning to
     * one log line instead of one per message.
     */
    private static final Set<String> slowRegexes = ConcurrentHashMap.newKeySet();

    public static boolean isSlowRegex(String regex) {
        return slowRegexes.contains(regex);
    }

    public static int[] searchPattern(String regex, byte[] text) throws PatternException {
        long startedAt = System.nanoTime();
        Matcher matcher = Pattern.compile(regex).matcher(new String(text));
        boolean found = matcher.find();
        long elapsed = (System.nanoTime() - startedAt) / 1_000_000;
        if (elapsed >= SLOW_MATCH_MILLIS && slowRegexes.add(regex)) {
            System.out.println("[!] Slow capture regex: " + elapsed + " ms on a " + text.length
                    + " byte message. Anchor it on a literal prefix, or make the quantifiers possessive"
                    + " (e.g. {20,}+), otherwise it will keep stalling every tool that uses it: " + regex);
        }
        if (found) {
            return new int[] { matcher.start(1), matcher.end(1) };
        }
        throw new PatternException(regex);
    }

    public OperationResult searchAndDecrypt(CapturePattern pattern, byte[] content, LogData logData)
            throws IOException, InterruptedException, PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), content);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = new String(content).substring(beginIndex, endIndex);
        OperationResult commandOutput = decryptWithCache(pattern, cipherText);
        if (pattern.shouldSaveToLog() && !commandOutput.isFailed()) {
            logData.update(cipherText, commandOutput.getOutput(), pattern.getName(), "Decrypt");
            config.writeLog(logData);
        }
        return commandOutput;
    }

    /**
     * Decrypt with cache fallback. On success: caches the result if pattern has
     * caching enabled. On failure: returns cached result if available.
     */
    private OperationResult decryptWithCache(CapturePattern pattern, String cipherText)
            throws IOException, InterruptedException {
        DecryptionCache decryptionCache = config.getDecryptionCache();
        OperationResult commandOutput = decrypt(pattern, cipherText);
        if (pattern.shouldUseCacheSystem()) {
            // Treat garbage (likely wrong-key) output like a soft failure: never cache it,
            // and fall back to a previously cached good value if one exists.
            boolean garbage = !commandOutput.isFailed() && pattern.shouldDetectGarbage()
                    && GarbageDetector.looksLikeGarbage(commandOutput.getOutput());
            if (!commandOutput.isFailed() && !garbage) {
                decryptionCache.put(cipherText, commandOutput.getOutput());
            } else {
                String cachedOutput = decryptionCache.get(cipherText);
                if (cachedOutput != null) {
                    OperationResult fallback = new OperationResult(cachedOutput, commandOutput.getOutput());
                    if (garbage) {
                        fallback.markGarbage(); // so the UI can say it fell back due to garbage, not a failure
                    }
                    return fallback;
                }
                if (garbage) {
                    commandOutput.markGarbage();
                }
            }
        }
        return commandOutput;
    }

    private OperationResult decrypt(CapturePattern pattern, String cipherText)
            throws IOException, InterruptedException {
        if (pattern.usesEngine()) {
            try {
                CryptoEngine engine = CryptoEngineRegistry.get(pattern.getEngineId());
                String result = engine.decrypt(cipherText, pattern.getEngineParams());
                return new OperationResult(result, 0);
            } catch (CryptoException e) {
                return new OperationResult(e.getMessage(), 1);
            }
        }
        ShellCommand command = new ShellCommand(pattern.getDecCommand(), cipherText);
        return command.execute();
    }
}