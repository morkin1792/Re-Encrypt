package reencrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;


public class Utils {
    public static void log(PrintWriter stdout, String message) {
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

    public static String getHash( byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {}
        md5.update(cipherText);
        return new BigInteger(1,md5.digest()).toString(16);
    }
}
