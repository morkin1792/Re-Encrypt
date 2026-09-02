package reencrypt;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

import reencrypt.exception.CommandException;

public class ShellCommand {
    String command;
    File tempFile;
    private File stderrFile;
    private int lastExitCode;

    public ShellCommand(String command, String text) throws IOException {
        this.tempFile = null;
        patch(command, text);
    }

    private void patch(String rawCommand, String text) throws IOException {
        this.command = rawCommand.replace(Config.dataMarker, text);
        if (this.command.contains(Config.fileMarker)) {
            File tempFile = createPrivateTempFile("reencrypt-", ".input");
            this.tempFile = tempFile;
            Files.write(tempFile.toPath(), text.getBytes());
            this.command = this.command.replace(Config.fileMarker, tempFile.getPath());
        }
    }

    /**
     * Temp file readable only by the current user. This file holds decrypted plaintext, so the
     * default 0644 of File.createTempFile would expose it to every local account.
     */
    private static File createPrivateTempFile(String prefix, String suffix) throws IOException {
        try {
            return Files.createTempFile(prefix, suffix,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).toFile();
        } catch (UnsupportedOperationException e) {
            // Windows: no POSIX permissions. The per-user temp dir is already ACL-restricted;
            // narrow the file itself as far as the File API allows.
            File f = File.createTempFile(prefix, suffix);
            f.setReadable(false, false);
            f.setWritable(false, false);
            f.setReadable(true, true);
            f.setWritable(true, true);
            return f;
        }
    }

    public OperationResult execute() throws IOException, InterruptedException {
        try {
            String result = new String(runProcess(true));
            // Remove the last newline char if present (echo puts a newline usually)
            // But don't trim other whitespaces
            if (result.endsWith("\r\n")) {
                result = result.substring(0, result.length() - 2);
            } else if (result.endsWith("\n")) {
                result = result.substring(0, result.length() - 1);
            }

            return new OperationResult(result, lastExitCode);
        } finally {
            DeleteTempFile();
        }
    }

    /**
     * Execute and return the raw stdout bytes (no newline trimming), throwing on a
     * non-zero exit code. Use this when binary output must be preserved exactly
     * (e.g. a command emitting DER-encoded key bytes).
     *
     * stderr is kept OUT of the returned bytes: a command that exits 0 while printing a warning
     * (openssl deprecation notices are the usual culprit) would otherwise splice that text into the
     * key material and fail much later with a confusing parse error. It is still reported on failure.
     */
    public byte[] executeRawChecked() throws IOException, InterruptedException, CommandException {
        try {
            byte[] raw = runProcess(false);
            if (lastExitCode != 0) {
                String stderr = readStderrFile();
                throw new CommandException("Command exited with code " + lastExitCode
                        + (stderr.isEmpty() ? "" : "\nStderr:\n" + stderr)
                        + "\nOutput:\n" + new String(raw));
            }
            return raw;
        } finally {
            DeleteTempFile();
        }
    }

    private byte[] runProcess(boolean mergeStderr) throws IOException, InterruptedException {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder builder;

        if (os.contains("win")) {
            builder = new ProcessBuilder("cmd.exe", "/c", command);
        } else {
            builder = new ProcessBuilder("bash", "-c", command);
        }

        if (mergeStderr) {
            builder.redirectErrorStream(true);
        } else {
            // Redirect to a file rather than reading a second pipe: draining one pipe while the
            // other fills its buffer would deadlock.
            this.stderrFile = createPrivateTempFile("reencrypt-", ".err");
            builder.redirectError(this.stderrFile);
        }
        Process process = builder.start();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream in = process.getInputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }

        lastExitCode = process.waitFor();
        return output.toByteArray();
    }

    private String readStderrFile() {
        if (this.stderrFile == null) {
            return "";
        }
        try {
            return new String(Files.readAllBytes(this.stderrFile.toPath())).trim();
        } catch (IOException e) {
            return "";
        }
    }

    private void DeleteTempFile() {
        if (this.tempFile != null) {
            this.tempFile.delete();
        }
        if (this.stderrFile != null) {
            this.stderrFile.delete();
        }
    }
}
