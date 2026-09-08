package reencrypt.analysis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reencrypt.engine.EncodingUtils;

/**
 * Offline heuristic analysis of a ciphertext string. Works in layers, most-probable first:
 * after {@link #preprocess} strips wrapping junk, Level 1 ({@code detectDirect}) treats the
 * whole value as one ciphertext (JWT/JWE incl. nonstandard {@code enc} like A256CTR, OpenSSL
 * {@code Salted__}, AES block-size / RSA modulus-size hints, peeling an outer Base64/Hex
 * wrapper). When that finds nothing actionable it tries alternate encodings + a nested decode
 * ({@code detectAlternateFormats}). Separately, {@link #bestSplit} interprets the value as
 * several concatenated ciphertexts (delimiter or equal-size splits). Produces ranked
 * {@link Suggestion}s that can seed a new pattern.
 */
public class CipherAnalyzer {

    public static class AnalysisResult {
        public final String outerEncoding; // "Base64" | "Base64URL" | "Hex" | "Raw"
        public final int rawLength;
        public final int decodedLength; // -1 if not decodable
        public final List<Suggestion> suggestions;

        AnalysisResult(String outerEncoding, int rawLength, int decodedLength, List<Suggestion> suggestions) {
            this.outerEncoding = outerEncoding;
            this.rawLength = rawLength;
            this.decodedLength = decodedLength;
            this.suggestions = suggestions;
        }
    }

    // A(keysize)(mode) — generic so nonstandard JWE enc values (e.g. A256CTR) still map.
    private static final Pattern JWE_ENC = Pattern.compile("A(128|192|256)(GCM|CBC-HS(?:256|384|512)|CBC|CTR|CFB|OFB|ECB)",
            Pattern.CASE_INSENSITIVE);

    public static AnalysisResult analyze(String inputRaw) {
        List<Suggestion> out = new ArrayList<>();
        String input = preprocess(inputRaw);
        if (input.isEmpty()) {
            return new AnalysisResult("Raw", 0, -1, out);
        }

        String enc = detectEncoding(input);
        byte[] decoded = tryDecode(input, enc);
        int decodedLen = decoded == null ? -1 : decoded.length;

        // Level 1: treat the whole value as one ciphertext (most probable, easiest to test).
        detectDirect(input, enc, decoded, out);

        // If nothing actionable, hypothesis (b): maybe a different encoding than auto-detected.
        if (!hasEncryptionFinding(out)) {
            detectAlternateFormats(input, enc, out);
        }

        appendEntropySuggestions(decoded, out); // v2 hook (no-op)

        out.sort((a, b) -> Integer.compare(b.getConfidence(), a.getConfidence()));
        return new AnalysisResult(enc, input.length(), decodedLen, out);
    }

    /**
     * Strip junk that wraps the ciphertext but isn't part of it: surrounding whitespace, a
     * matched quote pair, and leading/trailing bracket/quote characters. Never strips Base64
     * padding ('='), the Base64 alphabet, or '.' (JWT/JWE separator).
     */
    static String preprocess(String raw) {
        if (raw == null) {
            return "";
        }
        String s = raw.strip();
        boolean changed = true;
        while (changed && !s.isEmpty()) {
            changed = false;
            if (s.length() >= 2) {
                char a = s.charAt(0);
                char b = s.charAt(s.length() - 1);
                if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                    s = s.substring(1, s.length() - 1).strip();
                    changed = true;
                    continue;
                }
            }
            if (!s.isEmpty() && isWrappingJunk(s.charAt(0))) {
                s = s.substring(1).strip();
                changed = true;
            }
            if (!s.isEmpty() && isWrappingJunk(s.charAt(s.length() - 1))) {
                s = s.substring(0, s.length() - 1).strip();
                changed = true;
            }
        }
        return s;
    }

    private static boolean isWrappingJunk(char c) {
        return Character.isWhitespace(c) || "\"'{}[]()<>`".indexOf(c) >= 0;
    }

    /** Level-1 structural + byte detectors on the value under its auto-detected encoding. */
    private static void detectDirect(String input, String enc, byte[] decoded, List<Suggestion> out) {
        boolean decodedIsText = isPrintableText(decoded);
        String uiEnc = uiEncoding(enc);

        detectJwtJwe(input, "", out);
        if (decoded != null && decodedIsText && !"Raw".equals(enc)) {
            String unwrapped = new String(decoded, StandardCharsets.UTF_8).trim();
            detectJwtJwe(unwrapped, enc + "-wrapped ", out);
        }

        if (!"Raw".equals(enc) && decoded != null && !decodedIsText) {
            detectOpenSsl(decoded, uiEnc, out);
            detectBlockAndRsa(decoded, uiEnc, out);
        } else if (!"Raw".equals(enc) && decodedIsText && out.isEmpty()) {
            out.add(encodedTextSuggestion(peelTextLayers(enc, decoded)));
        }
    }

    /** Max decode hops while peeling nested encodings; the first decode counts as hop 1. */
    private static final int MAX_PEEL_HOPS = 3;

    /** Under this length a readable value is taken as the plaintext, not as another layer. */
    private static final int MIN_PEEL_INPUT = 8;

    /** One decode step of a peel: the encoding used and the text it produced. */
    private static class Layer {
        final String enc;
        final String text;

        Layer(String enc, String text) {
            this.enc = enc;
            this.text = text;
        }
    }

    /**
     * Peel nested text encodings (e.g. Base64 of Base64 of a plain value): keep decoding while
     * the result stays readable text and still looks encoded. Stops after {@link #MAX_PEEL_HOPS},
     * on a value too short to plausibly be another layer, or as soon as a decode yields
     * non-text bytes. Every layer is returned, so a spurious last hop -- ordinary text that
     * happens to match the Base64 alphabet and decodes to printable junk -- loses nothing.
     */
    private static List<Layer> peelTextLayers(String firstEnc, byte[] firstDecoded) {
        List<Layer> layers = new ArrayList<>();
        layers.add(new Layer(firstEnc, new String(firstDecoded, StandardCharsets.UTF_8).trim()));
        while (layers.size() < MAX_PEEL_HOPS) {
            String current = layers.get(layers.size() - 1).text;
            if (current.length() < MIN_PEEL_INPUT) {
                break;
            }
            String enc = detectEncoding(current);
            if ("Raw".equals(enc)) {
                break;
            }
            byte[] d = tryDecode(current, enc);
            if (d == null || d.length == 0 || !isPrintableText(d)) {
                break;
            }
            String next = new String(d, StandardCharsets.UTF_8).trim();
            if (next.isEmpty() || next.equals(current)) {
                break;
            }
            layers.add(new Layer(enc, next));
        }
        return layers;
    }

    /**
     * The "this is encoding, not encryption" note, naming the whole decode chain. Actionable via
     * Custom Command when every layer has a command form: the value still has to be decoded to be
     * read and re-encoded to be sent, so a pattern is as useful here as it is for real ciphertext.
     */
    private static Suggestion encodedTextSuggestion(List<Layer> layers) {
        List<String> encs = new ArrayList<>();
        StringBuilder chain = new StringBuilder();
        for (Layer l : layers) {
            encs.add(l.enc);
            if (chain.length() > 0) {
                chain.append(" \u2192 ");
            }
            chain.append(l.enc);
        }
        StringBuilder expl = new StringBuilder(chain)
                .append(" decoding gives a readable text:\n")
                .append(layers.get(layers.size() - 1).text);
        if (layers.size() > 1) {
            expl.append("\n\nIntermediate layers:");
            for (int i = 0; i < layers.size() - 1; i++) {
                expl.append("\n").append(i + 1).append(". after ").append(layers.get(i).enc).append(": ")
                        .append(preview(layers.get(i).text));
            }
        }

        String title = "Looks like encoded text, not encryption";
        String dec = EncodingCommands.decodeCommand(encs);
        String enc = EncodingCommands.encodeCommand(encs);
        if (dec == null || enc == null) {
            return Suggestion.info(title, expl.toString(), 50);
        }
        expl.append("\n\nCreate pattern seeds a Custom Command pattern that runs this chain, so the ")
                .append("value shows up decoded and is re-encoded on send.");
        return Suggestion.command(title, expl.toString(), 50, dec, enc);
    }

    /** One-line, length-capped rendering of an intermediate layer. */
    private static String preview(String s) {
        String one = s.replaceAll("\\s+", " ").trim();
        return one.length() > 120 ? one.substring(0, 120) + "\u2026 (" + s.length() + " chars)" : one;
    }

    /**
     * Hypothesis (b): the value uses a different encoding than auto-detected. Try the other
     * encodings on the raw value, plus one nested (double) decode, re-running the detectors
     * with a confidence penalty and an "(as &lt;enc&gt;)" title prefix. Deduped against
     * suggestions already found.
     */
    private static void detectAlternateFormats(String input, String primaryEnc, List<Suggestion> out) {
        for (String enc : new String[] { "Base64", "Base64URL", "Hex" }) {
            if (enc.equals(primaryEnc)) {
                continue;
            }
            byte[] d = tryDecode(input, enc);
            if (d == null || d.length == 0) {
                continue;
            }
            List<Suggestion> alt = new ArrayList<>();
            if (isPrintableText(d)) {
                detectJwtJwe(new String(d, StandardCharsets.UTF_8).trim(), enc + "-wrapped ", alt);
            } else {
                detectOpenSsl(d, uiEncoding(enc), alt);
                detectBlockAndRsa(d, uiEncoding(enc), alt);
            }
            for (Suggestion s : alt) {
                addPenalized(out, s, "as " + enc, 15);
            }
        }

        // Nested decode (e.g. Base64 of Base64 of a JWE, or Base64 of a hex blob).
        byte[] first = tryDecode(input, "Raw".equals(primaryEnc) ? "Base64" : primaryEnc);
        if (first != null && isPrintableText(first)) {
            String inner = new String(first, StandardCharsets.UTF_8).trim();
            String innerEnc = detectEncoding(inner);
            if (!"Raw".equals(innerEnc)) {
                byte[] second = tryDecode(inner, innerEnc);
                if (second != null && second.length > 0) {
                    List<Suggestion> alt = new ArrayList<>();
                    if (isPrintableText(second)) {
                        detectJwtJwe(new String(second, StandardCharsets.UTF_8).trim(), "double-decoded ", alt);
                    } else {
                        detectOpenSsl(second, uiEncoding(innerEnc), alt);
                        detectBlockAndRsa(second, uiEncoding(innerEnc), alt);
                    }
                    for (Suggestion s : alt) {
                        addPenalized(out, s, "nested", 20);
                    }
                }
            }
        }
    }

    /** Add a speculative suggestion with a penalty + prefix; dedupe actionable schemes. */
    private static void addPenalized(List<Suggestion> out, Suggestion s, String label, int penalty) {
        int conf = Math.max(5, s.getConfidence() - penalty);
        Suggestion adj = s.indicatesEncryption()
                ? Suggestion.engine("(" + label + ") " + s.getTitle(), s.getExplanation(), conf, s.getEngineId(),
                        s.getEngineParams())
                : Suggestion.info("(" + label + ") " + s.getTitle(), s.getExplanation(), conf);
        if (adj.indicatesEncryption()) {
            for (Suggestion e : out) {
                if (sameScheme(e, adj)) {
                    return;
                }
            }
        }
        out.add(adj);
    }

    private static boolean sameScheme(Suggestion a, Suggestion b) {
        return Objects.equals(a.getEngineId(), b.getEngineId())
                && Objects.equals(a.getEngineParams(), b.getEngineParams());
    }

    /**
     * Whether a cipher was already identified. Deliberately not {@code isActionable}: the
     * encoded-text finding is actionable but is precisely the case where the alternate-format
     * hypotheses are still worth trying (e.g. a JWE hiding under a second Base64 layer).
     */
    private static boolean hasEncryptionFinding(List<Suggestion> out) {
        for (Suggestion s : out) {
            if (s.indicatesEncryption()) {
                return true;
            }
        }
        return false;
    }

    // ===== Hypothesis (a): the value is several ciphertexts concatenated =====

    /** A way to split the value into independent parts, with a human reason and a score. */
    public static class SplitResult {
        public final List<String> parts;
        public final String reason;
        public final int score;
        public final char delimiter; // the delimiter used, or '\0' for an equal-size / no split

        SplitResult(List<String> parts, String reason, int score, char delimiter) {
            this.parts = parts;
            this.reason = reason;
            this.score = score;
            this.delimiter = delimiter;
        }

        static SplitResult none() {
            return new SplitResult(new ArrayList<>(), "", 0, '\0');
        }
    }

    // Delimiters to try, most-likely first. NOT '=' (Base64 padding) — splitting on it breaks Base64.
    private static final char[] DELIMS = { '.', '|', ':', ';', ',', '~', '#', '&', ' ' };

    /**
     * Try to interpret the value as several values concatenated: split on common delimiters and
     * into 2..5 equal-size blocks, score the candidates, and return the best (delimiter splits
     * rank above equal-size). A delimiter split is kept when every part is token-like and at
     * least one part is a confirmed ciphertext — the rest may be metadata or keys. Returns an
     * empty {@link SplitResult} when nothing qualifies; a real JWT/JWE, or a value that as a
     * whole is just a single encoding of readable text, is never split.
     */
    public static SplitResult bestSplit(String raw) {
        String input = preprocess(raw);
        if (input.length() < 32) { // need room for at least two ~16-char parts
            return SplitResult.none();
        }
        // A value that as a whole is one clean encoding of readable text (e.g. Base64 of a PEM
        // key) is just an encoding, not several ciphertexts — never split it.
        String wholeEnc = detectEncoding(input);
        if (!"Raw".equals(wholeEnc)) {
            byte[] whole = tryDecode(input, wholeEnc);
            if (whole != null && isPrintableText(whole)) {
                return SplitResult.none();
            }
        }
        // A real JWT/JWE is dot-separated; never split it.
        String[] dotParts = input.split("\\.", -1);
        if ((dotParts.length == 3 || dotParts.length == 5) && hasJoseHeader(dotParts[0])) {
            return SplitResult.none();
        }

        SplitResult best = SplitResult.none();

        // Delimiter splits: tokens separated by a non-alphanumeric character. Accept when every
        // part is token-like (so prose isn't carved up) and at least two parts are substantial
        // encoded blobs. We do NOT require any part to be a confirmed ciphertext — the parts may
        // all just be base64/hex; trying each of them is still useful. Other parts may be
        // metadata (e.g. "RSA", "enc", "P-256"), a key, or a short flag.
        for (char d : DELIMS) {
            int at = input.indexOf(d);
            if (at <= 0 || at >= input.length() - 1) {
                continue; // delimiter must be interior
            }
            String[] parts = input.split(Pattern.quote(String.valueOf(d)), -1);
            if (parts.length < 2) {
                continue;
            }
            int blobs = 0;
            int meaningful = 0;
            boolean coherent = true;
            for (String p : parts) {
                String t = p.trim();
                if (!isTokenLike(t)) {
                    coherent = false;
                    break;
                }
                boolean blob = looksLikeEncodedBlob(t);
                if (blob) {
                    blobs++;
                }
                if (blob || decodesCleanly(t)) {
                    meaningful++;
                }
            }
            // Accept a clean token structure with at least one substantial encoded blob and at
            // least two meaningful parts (substantial blobs or cleanly-decoding tokens such as
            // "RSA"/"enc"/"P-256"). We don't require any part to be a confirmed ciphertext.
            if (!coherent || blobs < 1 || meaningful < 2) {
                continue;
            }
            int score = scoreSplit(parts, true, d, blobs);
            if (score > best.score) {
                best = new SplitResult(toTrimmedList(parts), "separated by '" + d + "'", score, d);
            }
        }

        // Equal-size splits (2..5): a blind cut with no delimiter to confirm it, so require every
        // block to be a confirmed ciphertext (otherwise the cut almost certainly landed wrong).
        for (int n = 2; n <= 5; n++) {
            if (input.length() % n != 0) {
                continue;
            }
            int size = input.length() / n;
            String[] parts = new String[n];
            boolean allCipher = true;
            for (int i = 0; i < n; i++) {
                parts[i] = input.substring(i * size, (i + 1) * size);
                if (!isCiphertextPart(parts[i])) {
                    allCipher = false;
                }
            }
            if (!allCipher) {
                continue;
            }
            int score = scoreSplit(parts, false, '\0', n);
            if (score > best.score) {
                best = new SplitResult(toTrimmedList(parts), n + " equal-size blocks", score, '\0');
            }
        }

        return best.parts.size() >= 2 ? best : SplitResult.none();
    }

    /** A substantial encoded blob: ≥16 chars, a recognized encoding, and high entropy. */
    private static boolean looksLikeEncodedBlob(String p) {
        if (p == null || p.length() < 16 || "Raw".equals(detectEncoding(p))) {
            return false;
        }
        return EntropyUtil.shannonBitsPerByte(p) >= 3.5;
    }

    /** True when this part is a confirmed ciphertext: a valid encoding that decodes to ≥16 binary bytes. */
    static boolean isCiphertextPart(String s) {
        String enc = detectEncoding(s);
        if ("Raw".equals(enc)) {
            return false;
        }
        byte[] d = tryDecode(s, enc);
        return d != null && d.length >= 16 && !isPrintableText(d);
    }

    /** Token-like: non-empty and made only of encoding characters (no spaces / prose). */
    private static boolean isTokenLike(String s) {
        return !s.isEmpty() && s.matches("[A-Za-z0-9+/=_.\\-]+");
    }

    /** True when the value is a recognized encoding that decodes without error (any length). */
    private static boolean decodesCleanly(String s) {
        String enc = detectEncoding(s);
        return !"Raw".equals(enc) && tryDecode(s, enc) != null;
    }

    private static int scoreSplit(String[] parts, boolean delimiter, char d, int strongParts) {
        int score = delimiter ? 60 : 40;
        if (delimiter && (d == '.' || d == '|' || d == ':' || d == ';')) {
            score += 10;
        } else if (delimiter && d != ' ') {
            score += 3;
        }
        score += 8 * Math.min(strongParts, 3); // reward substantial encoded parts
        score -= 3 * (parts.length - 2);        // mild preference for fewer parts
        return score;
    }

    private static List<String> toTrimmedList(String[] arr) {
        List<String> l = new ArrayList<>();
        for (String s : arr) {
            l.add(s.trim());
        }
        return l;
    }

    private static boolean hasJoseHeader(String firstPart) {
        try {
            String json = new String(EncodingUtils.decodeBase64Url(firstPart), StandardCharsets.UTF_8);
            return extractJson(json, "alg") != null;
        } catch (Exception e) {
            return false;
        }
    }

    // ===== Structural detectors =====

    private static void detectJwtJwe(String text, String wrapLabel, List<Suggestion> out) {
        if (text.indexOf('.') < 0) {
            return;
        }
        String[] parts = text.split("\\.", -1);
        if (parts.length != 3 && parts.length != 5) {
            return;
        }
        String headerJson;
        try {
            headerJson = new String(EncodingUtils.decodeBase64Url(parts[0]), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return;
        }
        String alg = extractJson(headerJson, "alg");
        String enc = extractJson(headerJson, "enc");

        if (parts.length == 3 && alg != null && enc == null) {
            out.add(Suggestion.info(wrapLabel + "JWT (signed, not encrypted)",
                    "This is a 3-part JWS/JWT (alg=" + alg + "). It is signed, not encrypted — the payload "
                            + "(middle segment) is already Base64URL-decodable, so there is nothing to decrypt.",
                    95));
        } else if (parts.length == 5 && enc != null) {
            HashMap<String, String> p = mapJweEnc(enc);
            String note = wrapLabel.isEmpty() ? "" : " It was " + wrapLabel.trim() + " — decode that layer first.";
            out.add(Suggestion.engine(wrapLabel + "JWE token (enc=" + enc + ")",
                    "5-part JWE compact token (alg=" + alg + ", enc=" + enc + "). Use AES with the JWE structure; "
                            + "you'll need the content-encryption key (CEK), usually Base64." + note,
                    90, "aes", p));
        }
    }

    private static HashMap<String, String> mapJweEnc(String enc) {
        HashMap<String, String> p = params("ciphertextStructure", "jwe", "keyFormat", "Base64", "keySource", "text");
        String mode = "GCM";
        Matcher m = JWE_ENC.matcher(enc);
        if (m.find()) {
            String tok = m.group(2).toUpperCase();
            if (tok.startsWith("GCM")) {
                mode = "GCM";
            } else if (tok.startsWith("CBC")) {
                mode = "CBC";
            } else {
                mode = tok; // CTR / CFB / OFB / ECB
            }
        }
        p.put("mode", mode);
        if ("GCM".equals(mode)) {
            p.put("gcmTagLength", "128");
        }
        if ("CBC".equals(mode)) {
            p.put("padding", "PKCS5Padding");
        }
        return p;
    }

    // ===== Byte detectors =====

    private static void detectOpenSsl(byte[] decoded, String uiEnc, List<Suggestion> out) {
        if (decoded.length < 16) {
            return;
        }
        String magic = new String(decoded, 0, 8, StandardCharsets.US_ASCII);
        if (!"Salted__".equals(magic)) {
            return;
        }
        out.add(Suggestion.engine("OpenSSL enc ('Salted__')",
                "Decoded bytes begin with the OpenSSL 'Salted__' magic (salt is bytes 9-16). This is `openssl enc` "
                        + "output. Defaulting to AES-256-CBC with EVP_BytesToKey/MD5 — switch keyDerivation to "
                        + "PBKDF2 or change the key size if the command used different options.",
                85, "aes",
                params("ciphertextStructure", "openssl", "mode", "CBC", "padding", "PKCS5Padding", "keyDerivation",
                        "evp_md5", "opensslKeyLength", "32", "encoding", uiEnc, "mirrorEncoding", "true")));
    }

    private static void detectBlockAndRsa(byte[] decoded, String uiEnc, List<Suggestion> out) {
        int n = decoded.length;
        if (n == 0) {
            return;
        }
        if (n == 128 || n == 256 || n == 384 || n == 512) {
            int bits = n * 8;
            out.add(Suggestion.engine("RSA (" + bits + "-bit block)",
                    "Decoded length is exactly " + n + " bytes = one RSA block for a " + bits + "-bit key. Likely "
                            + "RSA; you'll need the private key (PEM or DER).",
                    60, "rsa", params("encryptionScheme", "PKCS1", "encoding", uiEnc, "mirrorEncoding", "true")));
            out.add(Suggestion.engine("RSA with OAEP (" + bits + "-bit)",
                    "If PKCS#1 v1.5 fails, the token may use OAEP padding (commonly SHA-256).",
                    45, "rsa", params("encryptionScheme", "OAEP", "oaepDigest", "SHA-256", "encoding", uiEnc,
                            "mirrorEncoding", "true")));
            return; // exact RSA match — skip block-cipher noise
        }
        if (n % 16 == 0) {
            out.add(Suggestion.engine("AES block mode (CBC/ECB)",
                    "Decoded length (" + n + " bytes) is a multiple of 16 -> AES in a block mode (CBC or ECB). If an "
                            + "IV is prepended, switch the structure to IV + Ciphertext.",
                    55, "aes", params("ciphertextStructure", "raw", "mode", "CBC", "padding", "PKCS5Padding",
                            "encoding", uiEnc, "mirrorEncoding", "true")));
            if (n >= 32) {
                out.add(Suggestion.engine("AES with prepended IV (IV + Ciphertext)",
                        "If the first 16 bytes are the IV, use the IV + Ciphertext structure.",
                        45, "aes", params("ciphertextStructure", "iv_ct", "mode", "CBC", "padding", "PKCS5Padding",
                                "encoding", uiEnc, "mirrorEncoding", "true")));
            }
        } else {
            out.add(Suggestion.engine("AES stream mode (CTR/CFB/OFB) or GCM",
                    "Decoded length (" + n + " bytes) is not a multiple of 16 -> a stream mode (CTR/CFB/OFB), or GCM "
                            + "where the last 16 bytes are the tag (try IV + Ciphertext + Tag). Adjust mode/structure.",
                    30, "aes", params("ciphertextStructure", "raw", "mode", "CTR", "encoding", uiEnc,
                            "mirrorEncoding", "true")));
        }
    }

    /** v2 hook: entropy-based suggestions. Intentionally empty for now. */
    private static void appendEntropySuggestions(byte[] decoded, List<Suggestion> out) {
        // TODO v2: use EntropyUtil.shannonBitsPerByte(decoded) to distinguish encrypted vs encoded.
    }

    // ===== AI prompt =====

    public static String buildAiPrompt(String ciphertext, AnalysisResult r) {
        String ct = ciphertext == null ? "" : ciphertext;
        if (ct.length() > 4000) {
            ct = ct.substring(0, 4000) + "\n...(truncated)";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("You are helping configure the Burp Suite extension \"Re:Encrypt\" to decrypt a captured ciphertext.\n\n");
        sb.append("Ciphertext:\n").append(ct).append("\n\n");
        sb.append("Observed locally: outer encoding=").append(r.outerEncoding).append(", raw length=")
                .append(r.rawLength);
        if (r.decodedLength >= 0) {
            sb.append(", decoded length=").append(r.decodedLength);
        }
        sb.append(".\n\n");
        sb.append("Answer with a Re:Encrypt pattern file the user can import directly via\n");
        sb.append("Capturing + Processing > Import (or General Settings > Import all).\n\n");
        sb.append("Format, shown with a common case (AES-256-CBC, IV prefixed to the ciphertext, Base64):\n");
        sb.append("{\n");
        sb.append("  \"reencrypt\": 1,\n");
        sb.append("  \"patterns\": [{\n");
        sb.append("    \"name\": \"encrypted body\",\n");
        sb.append("    \"isRequest\": true,\n");
        sb.append("    \"patchProxy\": false,\n");
        sb.append("    \"patternType\": \"PARAMETER_JSON\",\n");
        sb.append("    \"patternInput\": \"data\",\n");
        sb.append("    \"captureRegex\": \"\\\"data\\\":\\\"(.*?)\\\"\",\n");
        sb.append("    \"urlTargetRegex\": \"\",\n");
        sb.append("    \"engineId\": \"aes\",\n");
        sb.append("    \"engineParams\": {\n");
        sb.append("      \"mode\": \"CBC\", \"padding\": \"PKCS5Padding\",\n");
        sb.append("      \"ciphertextStructure\": \"iv_ct\", \"encoding\": \"Base64\",\n");
        sb.append("      \"key\": \"REPLACE_WITH_KEY\", \"keyFormat\": \"UTF-8\"\n");
        sb.append("    }\n");
        sb.append("  }]\n");
        sb.append("}\n\n");
        sb.append("Any field you leave out takes its default, so a pattern only needs what matters. ");
        sb.append("urlTargetRegex is matched against the whole URL; empty means every request. Give each ");
        sb.append("pattern a distinct name - a name that already exists replaces that pattern.\n\n");
        sb.append("Allowed values: engineId aes | rsa | null (null = custom shell commands in ");
        sb.append("\"decCommand\"/\"encCommand\" using the {DATA} or {FILE} placeholder). ");
        sb.append("patternType HEADER | PARAMETER_URL_ENCODED | PARAMETER_JSON | WHOLE_BODY | CUSTOM_REGEX ");
        sb.append("(captureRegex must contain capturing group 1 - that span is what gets decrypted). ");
        sb.append("captureRegex is the regex the UI builds from patternType + patternInput, so keep the two ");
        sb.append("consistent: PARAMETER_JSON \"x\" gives \\\"x\\\":\\\"(.*?)\\\", HEADER \"X-Foo\" gives ");
        sb.append("(?i)X-Foo: (.*), PARAMETER_URL_ENCODED \"x\" gives x=(.*?)(?:&|$). For a free-form regex use ");
        sb.append("CUSTOM_REGEX with the same regex in both patternInput and captureRegex. ");
        sb.append("AES: mode CBC|ECB|GCM|CTR|CFB|OFB, padding PKCS5Padding|NoPadding|ISO10126Padding, ");
        sb.append("ciphertextStructure raw|iv_ct|iv_ct_tag|openssl|jwe, encoding Base64|Hex|Raw, ");
        sb.append("keyFormat/ivFormat UTF-8|Hex|Base64, keyDerivation evp_md5|pbkdf2_sha256. ");
        sb.append("RSA: encryptionScheme PKCS1|OAEP|Raw, oaepDigest SHA-1|SHA-256|SHA-384|SHA-512, with the ");
        sb.append("PEM in \"publicKey\"/\"privateKey\".\n");
        sb.append("Key material does not have to be pasted in: \"keySource\" (and likewise ivSource, ");
        sb.append("publicKeySource, privateKeySource) may be text (the default, the value itself), file (the ");
        sb.append("value is a path) or command (the value is a shell command whose output is the key, run for ");
        sb.append("every message - use it when the key is derived per session).\n\n");
        sb.append("Full field reference: https://github.com/morkin1792/Re-Encrypt\n\n");
        sb.append("Give the 1-3 most likely schemes, best first, each as one pattern in the array, and say ");
        sb.append("what key material the user must fill in. If it is a 3-part JWT, note that it is signed ");
        sb.append("(not encrypted) and there is nothing to decrypt. Name the product/framework if the format ");
        sb.append("is recognizable (e.g. Laravel, Rails, ASP.NET ViewState, Fernet).");
        return sb.toString();
    }

    // ===== Helpers =====

    /** Detected outer encoding label for display. */
    static String detectEncoding(String s) {
        String t = s.replaceAll("\\s", "");
        if (t.isEmpty()) {
            return "Raw";
        }
        if (t.matches("[0-9a-fA-F]+") && t.length() % 2 == 0) {
            return "Hex";
        }
        boolean hasUrl = t.indexOf('-') >= 0 || t.indexOf('_') >= 0;
        if (t.matches("[A-Za-z0-9+/]+={0,2}")) {
            return "Base64";
        }
        if (t.matches("[A-Za-z0-9_-]+={0,2}") && hasUrl) {
            return "Base64URL";
        }
        return "Raw";
    }

    /** Map a detected encoding to the value the engine UI accepts (Base64 / Hex / Raw). */
    private static String uiEncoding(String detected) {
        if ("Hex".equals(detected)) {
            return "Hex";
        }
        if ("Base64".equals(detected) || "Base64URL".equals(detected)) {
            return "Base64";
        }
        return "Raw";
    }

    private static byte[] tryDecode(String s, String enc) {
        try {
            switch (enc) {
            case "Hex":
                return EncodingUtils.hexToBytes(s.replaceAll("\\s", ""));
            case "Base64":
                return EncodingUtils.decode(s.replaceAll("\\s", ""), "Base64");
            case "Base64URL":
                return EncodingUtils.decodeBase64Url(s);
            default:
                return s.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isPrintableText(byte[] b) {
        if (b == null || b.length == 0) {
            return false;
        }
        int printable = 0;
        for (byte x : b) {
            int v = x & 0xff;
            if (v == 9 || v == 10 || v == 13 || (v >= 32 && v < 127)) {
                printable++;
            }
        }
        return printable >= b.length * 0.9;
    }

    private static String extractJson(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static HashMap<String, String> params(String... kv) {
        HashMap<String, String> m = new HashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }
}
