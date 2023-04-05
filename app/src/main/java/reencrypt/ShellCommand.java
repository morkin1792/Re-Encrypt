package reencrypt;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import reencrypt.exception.CommandException;

public class ShellCommand {
    String[] commandArray;
    File tempFile;
    // boolean useStdin;

    public ShellCommand(String command, String text) throws IOException {
        this.tempFile = null;
        patch(command, text);        
    }

    void patch(String commandString, String text) throws IOException {
        // this.useStdin = true;
		List<String> commandList = Arrays.asList(commandString.split(" "));
		for (int index = 0; index < commandList.size(); index++) {
			String word = commandList.get(index);
			if (word.equals(Config.argMarker)) {
				commandList.set(index, text);
                // this.useStdin = false;
			} 
            if (word.equals(Config.fileMarker)) {
                File tempFile = File.createTempFile("reencrypt-", ".input");
                this.tempFile = tempFile;
                Files.write(tempFile.toPath(), text.getBytes());
                commandList.set(index, tempFile.getPath());
                // this.useStdin = false;
            }
			if ( (word.startsWith("'") || word.startsWith("\"")) && 
				(word.endsWith("'") || word.endsWith("\""))) {
					commandList.set(index, word.substring(1, word.length()-1));
			}
		}
        this.commandArray = new String[commandList.size()];
		commandList.toArray(this.commandArray);
	}

    public String execute(boolean removeLastLF) throws CommandException, IOException {
        String result = null;
        try {
            Process process = Runtime.getRuntime().exec(commandArray);
            InputStream inputStream = process.getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            result = scanner.hasNext() ? scanner.next() : null;
            if (result == null) {
                throw new CommandException(String.join(" ", commandArray));
            }
            //if ends with \n removes it
            if (removeLastLF && result.charAt(result.length() - 1) == '\n')
                result = result.substring(0, result.length() - 1);
        } catch (Exception exception) {
            DeleteTempFile();
            throw exception;
        }
        DeleteTempFile();
        return result;
    }

    void DeleteTempFile() {
        if (this.tempFile != null) {
            this.tempFile.delete();
        }
    }
}
