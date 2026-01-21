package reencrypt;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;

public class ShellCommand {
    String command;
    File tempFile;

    public ShellCommand(String command, String text) throws IOException {
        this.tempFile = null;
        patch(command, text);
    }

    private void patch(String rawCommand, String text) throws IOException {
        this.command = rawCommand.replace(Config.dataMarker, text);
        if (this.command.contains(Config.fileMarker)) {
            File tempFile = File.createTempFile("reencrypt-", ".input");
            this.tempFile = tempFile;
            Files.write(tempFile.toPath(), text.getBytes());
            this.command = this.command.replace(Config.fileMarker, tempFile.getPath());
        }
    }

    public CommandOutput execute() throws IOException, InterruptedException {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            ProcessBuilder builder;

            if (os.contains("win")) {
                builder = new ProcessBuilder("cmd.exe", "/c", command);
            } else {
                builder = new ProcessBuilder("bash", "-c", command);
            }

            builder.redirectErrorStream(true);
            Process process = builder.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                char[] buffer = new char[4096];
                int bytesRead;
                while ((bytesRead = reader.read(buffer)) != -1) {
                    output.append(buffer, 0, bytesRead);
                }
            }

            int exitCode = process.waitFor();

            String result = output.toString();
            // Remove the last newline char if present (echo puts a newline usually)
            // But don't trim other whitespaces
            if (result.endsWith("\r\n")) {
                result = result.substring(0, result.length() - 2);
            } else if (result.endsWith("\n")) {
                result = result.substring(0, result.length() - 1);
            }

            return new CommandOutput(result, exitCode);
        } finally {
            DeleteTempFile();
        }
    }

    private void DeleteTempFile() {
        if (this.tempFile != null) {
            this.tempFile.delete();
        }
    }
}
