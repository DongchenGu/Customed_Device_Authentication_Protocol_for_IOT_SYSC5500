package ECC2;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

public class ECCencrypt {

    private static int KEY_SIZE = 192;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

//    public static void main(String args[]) {
//
//        try {
//            KeyPair keyPair = getKeyPair();
//            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
//            ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
//
//            String content = "abc";
//
//            byte[] cipherTxt = encrypt(content.getBytes(), pubKey);
//            byte[] clearTxt = decrypt(cipherTxt, priKey);
//            System.out.println("content:" + content);
//            System.out.println(cipherTxt.toString());
//            System.out.println("cipherTxt["+cipherTxt.length+"]:" + new String(cipherTxt));
//            System.out.println("clearTxt:" + new String(clearTxt));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            System.out.println("[main]-Exception:" + e.toString());
//        }
//
//
//    }


    public  KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");//BouncyCastle
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public  String getPublicKey(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    public  String getPrivateKey(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    public  byte[] encrypt(byte[] content, ECPublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(content);
    }

    public  byte[] decrypt(byte[] content, ECPrivateKey priKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(content);
    }
}
