package ECC2;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;

public class KeyDistribution {

    private static int DICT_SIZE = 10;
    private static int KEY_SIZE = 192;

    public  KeyPair GetKeyPairFromDictionary(){

        ArrayList<KeyPair> dictionary = new ArrayList<>();

        dictionary = get_key_dictionary();

        KeyPair keypair = get_random_keypair(dictionary);

        return keypair;

    }

    public  ArrayList<KeyPair> get_key_dictionary () {
        ArrayList<KeyPair> key_dict = new ArrayList<>();

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());

            KeyPair keyPair;
            for (int i = 0; i < DICT_SIZE; i++) {
                keyPair = keyPairGenerator.generateKeyPair();
                key_dict.add(keyPair);
            }

            return key_dict;
        } catch (Exception e) {}

        return key_dict;
    }

    public  KeyPair get_random_keypair (ArrayList<KeyPair> dictionary) {

        int random_index = (int) Math.random() * DICT_SIZE;

        return dictionary.get(random_index);
    }

}
