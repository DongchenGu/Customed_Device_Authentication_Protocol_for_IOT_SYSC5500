package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAencrypt {
    public  java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
    public  java.util.Base64.Encoder encoder = Base64.getEncoder();
    private  Map<String, String> RsaKeyPair = new HashMap<String,String>();

    public RSAencrypt() throws NoSuchAlgorithmException {
        generateKeyPair();
    }

//    public static void main(String[] args) throws Exception {
//        String text = "this is the plain text for the testing";
//        System.out.println(text);
//
//        RSAencrypt rsa = new RSAencrypt();
//        String publicKEY =rsa.getPublicKeyString();
//        String privateKEY = rsa.getPrivateKeyString();
//
//        String cipherText = rsa.encrypt(text,publicKEY);
//        System.out.println("加密信息如下");
//        System.out.println(cipherText);
//
//        String plainText =rsa.decrypt(cipherText,privateKEY);
//        System.out.println("解密后的信息如下");
//        System.out.println(plainText);
//
//    }



    public void generateKeyPair() throws NoSuchAlgorithmException {
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048);
         KeyPair keyPair = keyPairGenerator.generateKeyPair();
         RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
         RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
         String publicKeyString = encoder.encodeToString(rsaPublicKey.getEncoded());
         String privateKeyString = encoder.encodeToString(rsaPrivateKey.getEncoded());

         RsaKeyPair.put("publicKey", publicKeyString);
         RsaKeyPair.put("privateKey", privateKeyString);
}

    public String getPrivateKeyString(){
        return RsaKeyPair.get("privateKey");
    }
    public String getPublicKeyString(){
        return RsaKeyPair.get("publicKey");
    }


    public String encrypt(String text, String publicKeyString) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(decoder.decode(publicKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec2);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(text.getBytes("ISO-8859-1"));

        return new String(result,"ISO-8859-1");
    }

    public String decrypt(String text, String privateKeyString) throws Exception{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decoder.decode(privateKeyString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher =Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] result = cipher.doFinal(text.getBytes("ISO-8859-1"));

        return new String(result,"ISO-8859-1");
    }

}
