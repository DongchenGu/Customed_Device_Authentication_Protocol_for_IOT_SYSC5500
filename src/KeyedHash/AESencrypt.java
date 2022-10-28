package KeyedHash;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESencrypt {

    private  final String initVector = "encryptionIntVec";

    //使用AES加密
    public  byte[] AESencrypt(byte[] value,String key) {
        byte[] encrypted = null;
        try {
            
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            encrypted = cipher.doFinal(value);
            return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return encrypted;
    }
}

