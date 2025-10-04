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
        // Simple implementation without external libraries
        this.command = rawCommand.replace(Config.dataMarker, text);
        if (this.command.contains(Config.fileMarker)) {
            File tempFile = File.createTempFile("reencrypt-", ".input");
            this.tempFile = tempFile;
            Files.write(tempFile.toPath(), text.getBytes());
            this.command = this.command.replace(Config.fileMarker, tempFile.getPath());
        }
    }

    public String execute() throws IOException, InterruptedException {
        try {
            System.out.println("Executing command: " + command);
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
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(System.lineSeparator());
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                // throw new RuntimeException("Command exited with code " + exitCode +
                // "\nOutput:\n" + output);
                return "Command exited with code " + exitCode + "\nOutput:\n" + output;
            }
            return output.toString().trim();
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
