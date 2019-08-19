import com.panickapps.jsec.SymmetricEncryption;

public class SymmetricEncryptionTest {

    public static void main(String[] args) {

        final String input = "MyRandomInput";
        final String key = "MySecretKey";

        final String encrypted = SymmetricEncryption.encrypt(input, key);
        final String decrypted = SymmetricEncryption.decrypt(encrypted, key);

        System.out.println("Input => " + input);
        System.out.println("Encrypted => " + encrypted);
        System.out.println("Decrypted => " + decrypted);

    }

}
