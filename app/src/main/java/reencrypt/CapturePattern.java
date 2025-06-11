package reencrypt;

public class CapturePattern {
    boolean enabled;
    String name;
    String regex;
    String decCommand, encCommand;
    
    public CapturePattern(String name, String regex, String decCommand, String encCommand, boolean enabled) {
        this.enabled = enabled;
        this.regex = regex;
        this.name = name;
        this.decCommand = decCommand;
        this.encCommand = encCommand;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRegex() {
        return regex;
    }

    public String getName() {
        return name;
    }
    public String getDecCommand() {
        return decCommand;
    }
    public String getEncCommand() {
        return encCommand;
    }
    
    public void setRegex(String regex) {
        this.regex = regex;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public void setDecCommand(String decCommand) {
        this.decCommand = decCommand;
    }
    
    public void setEncCommand(String encCommand) {
        this.encCommand = encCommand;
    }

}
