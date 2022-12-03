package ECC2;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;
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
//            String content = "abcjhbhj";
//
//            byte[] cipherTxt = encrypt(content.getBytes("ISO-8859-1"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
//            String string = new String(cipherTxt, "ISO-8859-1");
//
//            byte[] clearTxt = decrypt(string.getBytes("ISO-8859-1"), Base64.getEncoder().encodeToString(priKey.getEncoded()));
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
        //调用封装好的字典，通过字典来获取
        KeyDistribution keyDistribution = new KeyDistribution();

        KeyPair keyPair = keyDistribution.GetKeyPairFromDictionary();

//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");//BouncyCastle
//        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
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

    public  byte[] encrypt(byte[] content, String publicKeyText) throws Exception {

        X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec2);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return  cipher.doFinal(content);

    }

    public  byte[] decrypt(byte[] content, String privateKeyText) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec5 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec5);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }
}
