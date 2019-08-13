package com.panickapps.javasecurity;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

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
 * Provides functionality for symmetric encryption using the AES algorithm.
 */
public class SymmetricEncryption {

    private static final String AES = "AES";
    private static final String CIPHER_INSTANCE = "AES/ECB/PKCS5Padding";

    private static SecretKeySpec secretKey;
    private static byte[] key;

    /**
     * Sets the encryption key.
     * @param key The key to use for encryption.
     * @throws NoSuchAlgorithmException
     */
    private static void setKey(final String key) throws NoSuchAlgorithmException {
        MessageDigest sha = null;
        SymmetricEncryption.key = key.getBytes(StandardCharsets.UTF_8);
        sha = MessageDigest.getInstance(HashType.SHA512.toString());
        SymmetricEncryption.key = sha.digest(SymmetricEncryption.key);
        SymmetricEncryption.key = Arrays.copyOf(SymmetricEncryption.key, 16);
        secretKey = new SecretKeySpec(SymmetricEncryption.key, AES);
    }

    /**
     * Encrypts a given text using a given key.
     * @param text The text to encrypt.
     * @param key The key to use for encryption.
     * @return Returns an encrypted version of the data as a String.
     */
    public static String encrypt(final String text, final String key) {
        try {
            setKey(key);
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts a given ciphertext using a given key.
     * @param ciphertext The ciphertext to decrypt.
     * @param key The key to use for decryption.
     * @return Returns a decrypted (original) string of the encrypted data.
     */
    public static String decrypt(final String ciphertext, final String key) {
        try {
            setKey(key);
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
