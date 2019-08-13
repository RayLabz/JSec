package com.panickapps.javasecurity;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricEncryption {

    private static KeyPair pair;
    private static Cipher cipher;

    static {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            pair = keyPairGen.generateKeyPair();
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(final String text) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] input = text.getBytes();
        cipher.update(input);
        return cipher.doFinal();
    }

    public static String decrypt(final byte[] cipherText) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        byte[] decipheredText = cipher.doFinal(cipherText);
        return new String(decipheredText);
    }

    public static String encryptedBytesToString(final byte[] ciphertext) {
        return new String(ciphertext, StandardCharsets.UTF_8);
    }

    public static PublicKey getPublicKey() {
        return pair.getPublic();
    }

    public static PrivateKey getPrivateKey() {
        return pair.getPrivate();
    }

    public static PublicKey getPublicKeyFromBytes(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PrivateKey getPrivateKeyFromBytes(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

}