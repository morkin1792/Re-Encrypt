package reencrypt.exception;

public class PatternException extends Exception {

    public PatternException(String regex) {
        super("[-] pattern not found: " + regex);
    }
}
