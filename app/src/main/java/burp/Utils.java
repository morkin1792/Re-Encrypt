package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.io.InputStream;
import java.util.Scanner;


public class Utils {
    public static String[] patchCommand(String commandString, String text) {
		List<String> command = Arrays.asList(commandString.split(" "));
		for (int index = 0; index < command.size(); index++) {
			String word = command.get(index);
			if (word.equals(Config.replaceMarker)) {
				command.set(index, text);
			}
			if ( (word.startsWith("'") || word.startsWith("\"")) && 
				(word.endsWith("'") || word.endsWith("\""))) {
					command.set(index, word.substring(1, word.length()-1));
			}
		}
		String[] array = new String[command.size()];
		command.toArray(array);
		return array;
	}

    public static String executeCommand(String[] command, boolean removeLastLF) throws Exception {
        String result = null;
        
        Process process = Runtime.getRuntime().exec(command);
        InputStream inputStream = process.getInputStream();
        Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
        result = scanner.hasNext() ? scanner.next() : null;
        if (result == null) {
            throw new Exception("failed running: " + String.join(" ", command));
        }
        //if ends with \n removes it
        if (removeLastLF && result.charAt(result.length() - 1) == '\n')
            result = result.substring(0, result.length() - 1);
        return result;
    }

    public static void Log(PrintWriter stdout, String message) {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        System.out.println();
        stdout.println("~" + dateFormat.format(date) + "~ " + message);
    }

    public static String stringify(Object object) throws IOException {
        var arrayOutputStream = new ByteArrayOutputStream();
        var objectOutputStream = new ObjectOutputStream(arrayOutputStream);
        objectOutputStream.writeObject(object);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(arrayOutputStream.toByteArray());
    }

    public static Object parse(String objectSerialized) throws IOException, ClassNotFoundException {
        var configBytes = Base64.getDecoder().decode(objectSerialized);
        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(configBytes));
        return objectInputStream.readObject();
    }
}
