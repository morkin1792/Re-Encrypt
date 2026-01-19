package reencrypt;

import reencrypt.exception.CommandException;

public class CommandOutput {
    String output, originalError;
    boolean cached;
    int exitCode;

    public CommandOutput(String output, int exitCode) {
        this.output = output;
        this.cached = false;
        this.exitCode = exitCode;
        this.originalError = "";
    }

    public CommandOutput(String output, String originalError) {
        this.output = output;
        this.cached = true;
        this.exitCode = -1;
        this.originalError = originalError;
    }

    public String getOutput() {
        return output;
    }

    public String getOutputCheckingExitCode() throws CommandException {
        if (exitCode != 0) {
            throw new CommandException("Command exited with code " + exitCode + "\nOutput:\n" + output);
        }
        return output;
    }

    public String getOriginalError() {
        return originalError;
    }

    public boolean isCached() {
        return cached;
    }

    public boolean isFailed() {
        return exitCode != 0;
    }

}
