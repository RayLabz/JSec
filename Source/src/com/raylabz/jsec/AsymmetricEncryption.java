package com.panickapps.jsec;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by PaNickApps - 2019
 * Visit http://www.panickapps.com
 *
 * Java Security Essentials - A simple encryption and hashing library for Java.
 * Provides methods for hashing, symmetric and asymmetric encryption.
 * Repository: https://github.com/panickapps/java-security-essentials
 * Guide: https://panickapps.github.io/Java-Security-Essentials/
 *
 * Apache 2.0 License
 */

/**
 * Provides functionality for asymmetric encryption using the RSA algorithm.
 */
public class AsymmetricEncryption {

    private static final String RSA = "RSA";
    private static final String CIPHER_INSTANCE = "RSA/ECB/PKCS1Padding";

    private static KeyPair pair;
    private static Cipher cipher;

    static {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA);
            keyPairGen.initialize(2048);
            pair = keyPairGen.generateKeyPair();
            cipher = Cipher.getInstance(CIPHER_INSTANCE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypts data using the specified public key.
     * @param input The data input as a byte array.
     * @return Returns a byte array of the encrypted data.
     */
    public static byte[] encrypt(final byte[] input) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            cipher.update(input);
            return cipher.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts data using the specified private key.
     * @param encryptedBytes The encrypted data to decrypt.
     * @return REturns a byte array of the decrypted data.
     */
    public static byte[] decrypt(final byte[] encryptedBytes) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
            return cipher.doFinal(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retrieves the current public key.
     * @return Returns a PublicKey.
     */
    public static PublicKey getPublicKey() {
        return pair.getPublic();
    }

    /**
     * Retrieves the current private key.
     * @return Returns a PrivateKey.
     */
    public static PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }

    /**
     * Converts a stored version of a public key as an array of bytes to a public key.
     * @param bytes The key data.
     * @return Returns a PublicKey.
     */
    public static PublicKey getPublicKeyFromBytes(final byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts a stored version of a private key as an array of bytes to a private key.
     * @param bytes The key data.
     * @return Returns a PrivateKey.
     */
    public static PrivateKey getPrivateKeyFromBytes(final byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytes);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sets the public-private key pair.
     * @param publicKey The public key.
     * @param privateKey The private key.
     */
    public static void setKeyPair(final PublicKey publicKey, final PrivateKey privateKey) {
        pair = new KeyPair(publicKey, privateKey);
    }

    /**
     * Setsthe public-private key pair.
     * @param keyPair The key pair.
     */
    public static void setKeyPair(final KeyPair keyPair) {
        pair = keyPair;
    }

}