import com.panickapps.javasecurity.AsymmetricEncryption;

import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricEncryptionTest {

    public static void main(String[] args) {

        final String input = "MyRandomInput";

            byte [] encrypted = AsymmetricEncryption.encrypt(input.getBytes());
            byte [] decrypted = AsymmetricEncryption.decrypt(encrypted);
            System.out.println("Input => " + input);
            System.out.println("Encrypted => " + new String(encrypted));
            System.out.println("Decrypted => " + new String(decrypted));

            //Getting the private key:
            PrivateKey privateKey = AsymmetricEncryption.getPrivateKey();
            PublicKey publicKey = AsymmetricEncryption.getPublicKey();

            //Getting keys as bytes:
            byte[] privateKeyBytes = privateKey.getEncoded();
            byte[] publicKeyBytes = publicKey.getEncoded();

            //Decoding keys from bytes:
            privateKey = AsymmetricEncryption.getPrivateKeyFromBytes(privateKeyBytes);
            publicKey = AsymmetricEncryption.getPublicKeyFromBytes(publicKeyBytes);

            //Setting external/received keys:
            AsymmetricEncryption.setKeyPair(publicKey, privateKey);

    }

}
