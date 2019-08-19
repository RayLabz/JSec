import com.panickapps.jsec.HashType;
import com.panickapps.jsec.Hashing;

public class HashingTest {

    public static void main(String[] args) {

        final String input = "MyRandomInput";
        System.out.println("Input: " + input);

        System.out.println();

        //Default:
        System.out.println("Default hashing (SHA512):");
        System.out.println(Hashing.hash(input));

        System.out.println();

        //MD5:
        System.out.println("MD5:");
        System.out.println(Hashing.hash(HashType.MD5, input.getBytes()));

        System.out.println();

        //SHA1:
        System.out.println("SHA1:");
        System.out.println(Hashing.hash(HashType.SHA1, input.getBytes()));

        System.out.println();

        //SHA256:
        System.out.println("SHA256:");
        System.out.println(Hashing.hash(HashType.SHA256, input.getBytes()));

        System.out.println();

        //SHA384:
        System.out.println("SHA384:");
        System.out.println(Hashing.hash(HashType.SHA384, input.getBytes()));

        System.out.println();

        //SHA512:
        System.out.println("SHA512:");
        System.out.println(Hashing.hash(HashType.SHA512, input.getBytes()));

        System.out.println();

        /*-------------------------------------- Salt Hashing --------------------------------------------------------*/

        System.out.println(" --- Hashing with salt --- ");
        System.out.println();

        //Creating salt:
        final byte[] salt = Hashing.salt();
        System.out.println("Generated salt as a String: " + (new String(salt)));

        System.out.println();

        //Default w/ salt:
        System.out.println("Default hashing (SHA512) w/ salt:");
        System.out.println(Hashing.hash(input.getBytes(), salt));

        System.out.println();

        //MD5 with salt:
        System.out.println("MD5 w/ salt:");
        System.out.println(Hashing.hash(HashType.MD5, input.getBytes(), salt));

        System.out.println();

        //SHA1 with salt:
        System.out.println("SHA1 w/ salt:");
        System.out.println(Hashing.hash(HashType.SHA1, input.getBytes(), salt));

        System.out.println();

        //SHA256 with salt:
        System.out.println("SHA256 w/ salt:");
        System.out.println(Hashing.hash(HashType.SHA256, input.getBytes(), salt));

        System.out.println();

        //SHA384 with salt:
        System.out.println("SHA384 w/ salt:");
        System.out.println(Hashing.hash(HashType.SHA384, input.getBytes(), salt));

        System.out.println();

        //SHA512 with salt:
        System.out.println("SHA512 w/ salt:");
        System.out.println(Hashing.hash(HashType.SHA512, input.getBytes(), salt));

        /*------------------------------------ Hashing raw data ------------------------------------------------------*/

        System.out.println();

        byte[] rawData = input.getBytes();
        System.out.println("Hashing raw data:");
        System.out.println(Hashing.hash(rawData));

    }

}
