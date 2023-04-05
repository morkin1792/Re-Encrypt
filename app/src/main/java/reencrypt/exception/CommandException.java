package reencrypt.exception;

public class CommandException extends Exception {

    public CommandException(String cmd) {
        super("[-] failed running: " + cmd);
    }
}
