package AES;

import javax.crypto.Cipher;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class AESencryption {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static final String CIPHER_ALGORITHM="AES/ECB/PKCS7Padding";

    public  java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
    public  java.util.Base64.Encoder encoder = Base64.getEncoder();

    public AESencryption() throws NoSuchAlgorithmException {
        generateKey();
    }

    public String generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);

        SecretKey secretKey = keyGenerator.generateKey();

        String AESKeyString = encoder.encodeToString(secretKey.getEncoded());

        return AESKeyString;
    }

    public String encrypt(String text, String KeyString) throws Exception {
        SecretKey secretKey = new SecretKeySpec(decoder.decode(KeyString), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] result = cipher.doFinal(text.getBytes("ISO-8859-1"));

        return new String(result,"ISO-8859-1");
    }

    public Key restoreKey(byte[] key) throws Exception {
        SecretKey restoredKey = new SecretKeySpec(key, "AES");
        return restoredKey;
    }

    public String decrypt(String text, String KeyString) throws Exception{
        SecretKey secretKey = new SecretKeySpec(decoder.decode(KeyString), "AES");

        Cipher cipher =Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] result = cipher.doFinal(text.getBytes("ISO-8859-1"));

        return new String(result,"ISO-8859-1");
    }
}
