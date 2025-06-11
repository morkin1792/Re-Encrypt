package reencrypt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Utils {
    public static String getHash( byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {}
        md5.update(cipherText);
        return new BigInteger(1,md5.digest()).toString(16);
    }
}
