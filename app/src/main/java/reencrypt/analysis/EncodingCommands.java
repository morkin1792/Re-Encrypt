package reencrypt.analysis;

import java.util.List;

import reencrypt.Config;

/**
 * Shell commands that decode and re-encode the plain text encodings {@link CipherAnalyzer}
 * recognises (Base64, Base64URL, Hex), so an "encoded text, not encryption" finding can seed a
 * working Custom Command pattern instead of only telling the user what the value is.
 *
 * <p>A chain is given outermost encoding first, the order {@code CipherAnalyzer} peels it in;
 * the encode direction walks the same list backwards. Both directions read {@code {FILE}} rather
 * than {@code {DATA}}: the encode direction is handed plaintext, which may contain quotes.
 *
 * <p>Two dialects only, POSIX and Windows, matching the two shells {@code ShellCommand} can spawn.
 * The POSIX commands use {@code openssl}/{@code xxd} so one string works on Linux and macOS alike
 * (GNU and BSD {@code base64} disagree on both the decode flag and on line wrapping); the Windows
 * ones shell out to PowerShell, since {@code cmd.exe} has no usable Base64 or hex converter.
 *
 * <p>The Windows form is constrained by how it reaches PowerShell. {@code ShellCommand} runs
 * {@code ProcessBuilder("cmd.exe", "/c", command)}, and Java wraps an argument containing spaces
 * in double quotes without escaping the quotes already inside it. {@code cmd /c} then sees more
 * than two quotes and falls back to "strip the first character and the last quote", which hands
 * PowerShell exactly the {@code -Command "..."} that was written here. That only holds while the
 * script itself contains <em>no</em> double quote of its own (every string literal below is
 * single-quoted) and no bare {@code %}, which cmd would try to expand.
 *
 * <p>The PowerShell script pipes {@code byte[]} from stage to stage and writes the result to the
 * raw stdout handle. Going through .NET strings instead would put the payload at the mercy of
 * the console code page, which is not UTF-8 on a default Windows install and would corrupt every
 * non-ASCII plaintext; only the encoded form, which is ASCII by definition, is read as text.
 */
public final class EncodingCommands {

    private EncodingCommands() {
    }

    /** True when this JVM would run commands through {@code cmd.exe} rather than {@code bash}. */
    public static boolean hostIsWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    public static String decodeCommand(List<String> encodings) {
        return decodeCommand(encodings, hostIsWindows());
    }

    public static String encodeCommand(List<String> encodings) {
        return encodeCommand(encodings, hostIsWindows());
    }

    /** @param windows build for {@code cmd.exe} instead of {@code bash} (exposed for tests) */
    public static String decodeCommand(List<String> encodings, boolean windows) {
        return build(encodings, true, windows);
    }

    /** @param windows build for {@code cmd.exe} instead of {@code bash} (exposed for tests) */
    public static String encodeCommand(List<String> encodings, boolean windows) {
        return build(encodings, false, windows);
    }

    /** @return null when any encoding in the chain has no command form. */
    private static String build(List<String> encodings, boolean decode, boolean windows) {
        if (encodings == null || encodings.isEmpty()) {
            return null;
        }
        // Encoding wraps from the inside out, so re-encoding replays the peel backwards.
        List<String> ordered = decode ? encodings : reversed(encodings);
        StringBuilder sb = new StringBuilder();
        for (String enc : ordered) {
            String stage = windows ? windowsStage(enc, decode) : posixStage(enc, decode);
            if (stage == null) {
                return null;
            }
            sb.append(stage);
        }
        return windows
                ? "powershell -NoProfile -Command \"$b=[IO.File]::ReadAllBytes('" + Config.fileMarker + "');" + sb
                        + "$o=[Console]::OpenStandardOutput();$o.Write($b,0,$b.Length);$o.Flush()\""
                : "cat '" + Config.fileMarker + "'" + sb;
    }

    private static List<String> reversed(List<String> in) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>(in);
        java.util.Collections.reverse(out);
        return out;
    }

    /** One stage of a bash pipeline, leading {@code " | "} included. */
    private static String posixStage(String enc, boolean decode) {
        switch (enc) {
        case "Base64":
            return decode ? " | openssl base64 -d -A" : " | openssl base64 -e -A";
        case "Base64URL":
            // openssl only speaks standard Base64: swap the alphabet, and restore the padding it
            // needs on the way in / strip it again on the way out.
            return decode
                    ? " | tr -- '-_' '+/'"
                            + " | awk '{n=length%4; printf \"%s%s\", $0, (n==2?\"==\":(n==3?\"=\":\"\"))}'"
                            + " | openssl base64 -d -A"
                    : " | openssl base64 -e -A | tr -- '+/' '-_' | tr -d '='";
        case "Hex":
            // xxd -p wraps at 60 columns; the captured value has to come back as one token.
            return decode ? " | xxd -r -p" : " | xxd -p | tr -d '\\n'";
        default:
            return null;
        }
    }

    /**
     * One statement of the PowerShell script, transforming the {@code byte[]} in {@code $b} in
     * place. The encoded side is decoded as ASCII rather than UTF-8 on purpose: it is ASCII by
     * construction, and ASCII cannot silently consume a stray byte the way UTF-8 can.
     */
    private static String windowsStage(String enc, boolean decode) {
        switch (enc) {
        case "Base64":
            return decode
                    ? "$b=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString($b).Trim());"
                    : "$b=[Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($b));";
        case "Base64URL":
            // -band 3 rather than %4: a bare % on a cmd.exe command line is best left alone.
            return decode
                    ? "$s=[Text.Encoding]::ASCII.GetString($b).Trim().Replace('-','+').Replace('_','/');"
                            + "$m=$s.Length -band 3;if($m -eq 2){$s+='=='}elseif($m -eq 3){$s+='='};"
                            + "$b=[Convert]::FromBase64String($s);"
                    : "$b=[Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($b)"
                            + ".TrimEnd('=').Replace('+','-').Replace('/','_'));";
        case "Hex":
            // @() so a zero- or one-byte result is still an array; ToString/Replace beats a
            // per-byte loop, and lowercases to match xxd so both dialects emit the same text.
            return decode
                    ? "$b=[byte[]]@([regex]::Matches([Text.Encoding]::ASCII.GetString($b).Trim(),'..')"
                            + "|ForEach-Object{[Convert]::ToByte($_.Value,16)});"
                    : "$b=[Text.Encoding]::ASCII.GetBytes([BitConverter]::ToString($b).Replace('-','').ToLower());";
        default:
            return null;
        }
    }
}
