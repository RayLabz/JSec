import com.panickapps.javasecurity.AsymmetricEncryption;
import com.panickapps.javasecurity.Hashing;
import com.panickapps.javasecurity.HashType;

import java.security.*;

public class Test {

    public static void main(String[] args) {

        final String input = "password";

        try {

            //Testing MD5:
            System.out.println(Hashing.hash(HashType.MD5, input));
            System.out.println(Hashing.hash(HashType.MD5, input));

            System.out.println();

            //Testing MD5 with salt:
            final byte[] salt = Hashing.salt();
            System.out.println(Hashing.hash(HashType.MD5, input, salt));
            System.out.println(Hashing.hash(HashType.MD5, input, salt));

            System.out.println();

            //Testing SHA1:
            System.out.println(Hashing.hash(HashType.SHA1, input));
            System.out.println(Hashing.hash(HashType.SHA1, input));

            System.out.println();

            //Testing SHA1 with salt:
            System.out.println(Hashing.hash(HashType.SHA1, input, salt));
            System.out.println(Hashing.hash(HashType.SHA1, input, salt));

            System.out.println();

            //Testing SHA256:
            System.out.println(Hashing.hash(HashType.SHA256, input));
            System.out.println(Hashing.hash(HashType.SHA256, input));

            System.out.println();

            //Testing SHA256 with salt:
            System.out.println(Hashing.hash(HashType.SHA256, input, salt));
            System.out.println(Hashing.hash(HashType.SHA256, input, salt));

            System.out.println();

            //Testing SHA384:
            System.out.println(Hashing.hash(HashType.SHA384, input));
            System.out.println(Hashing.hash(HashType.SHA384, input));

            System.out.println();

            //Testing SHA384 with salt:
            System.out.println(Hashing.hash(HashType.SHA384, input, salt));
            System.out.println(Hashing.hash(HashType.SHA384, input, salt));

            System.out.println();

            //Testing SHA512:
            System.out.println(Hashing.hash(HashType.SHA512, input));
            System.out.println(Hashing.hash(HashType.SHA512, input));

            System.out.println();

            //Testing SHA512 with salt:
            System.out.println(Hashing.hash(HashType.SHA512, input, salt));
            System.out.println(Hashing.hash(HashType.SHA512, input, salt));


        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        //----------------------------------------------------------------

        System.out.println();
        System.out.println();

        //AsymmetricEncryption:

        try {
            byte [] encrypted = AsymmetricEncryption.encrypt(input);
            System.out.println("Original => " + input);
            System.out.println("Encrypted => " + AsymmetricEncryption.encryptedBytesToString(encrypted));
            System.out.println("Decrypted => " + AsymmetricEncryption.decrypt(encrypted));

            //Getting the private key:
            PrivateKey privateKey = AsymmetricEncryption.getPrivateKey();
            PublicKey publicKey = AsymmetricEncryption.getPublicKey();

            //Getting keys as bytes:
            byte[] privateKeyBytes = AsymmetricEncryption.getPrivateKey().getEncoded();
            byte[] publicKeyBytes = AsymmetricEncryption.getPublicKey().getEncoded();

            //Decoding keys from bytes:
            privateKey = AsymmetricEncryption.getPrivateKeyFromBytes(privateKeyBytes);
            publicKey = AsymmetricEncryption.getPublicKeyFromBytes(publicKeyBytes);



        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
