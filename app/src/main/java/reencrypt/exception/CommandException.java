package reencrypt.exception;

public class CommandException extends Exception {
    String message;

    public CommandException(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
