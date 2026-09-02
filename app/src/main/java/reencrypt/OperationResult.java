package reencrypt;

import reencrypt.exception.CommandException;

public class OperationResult {
    String output, originalError;
    boolean cached;
    boolean garbage;
    int exitCode;

    public OperationResult(String output, int exitCode) {
        this.output = output;
        this.cached = false;
        this.exitCode = exitCode;
        this.originalError = "";
    }

    public OperationResult(String output, String originalError) {
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

    public boolean isGarbage() {
        return garbage;
    }

    public void markGarbage() {
        this.garbage = true;
    }

    public boolean isFailed() {
        return exitCode != 0;
    }

    public int getExitCode() {
        return exitCode;
    }

}
