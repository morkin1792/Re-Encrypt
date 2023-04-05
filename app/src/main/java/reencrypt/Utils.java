package reencrypt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Utils {
    // public static void log(PrintWriter stdout, String message) {
    //     DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    //     Date date = new Date();
    //     System.out.println();
    //     stdout.println("~" + dateFormat.format(date) + "~ " + message);
    // }

    public static String getHash( byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {}
        md5.update(cipherText);
        return new BigInteger(1,md5.digest()).toString(16);
    }
}
