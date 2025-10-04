package reencrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

public class Utils {
    public static String getHash(byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
        }
        md5.update(cipherText);
        return new BigInteger(1, md5.digest()).toString(16);
    }

    public static <T extends Serializable> String serialize(ArrayList<T> list) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(list);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    public static <T extends Serializable> ArrayList<T> deserialize(String s)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (ArrayList<T>) ois.readObject();
        }
    }
}
