package com.panickapps.javasecurity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Hashing {

    //Hashing:
    private static final String SHA_SALT_ALGORITHM = "SHA1PRNG";
    private static final String SHA_SALT_PROVIDER = "SUN";
    private static final HashType DEFAULT_HASHTYPE = HashType.SHA512;

    public static String hash(final HashType hashType, final String inputText, final byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashType.toString());
        md.update(salt);
        byte[] bytes = md.digest(inputText.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static String hash(final HashType hashType, final String inputText) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashType.toString());
        byte[] bytes = md.digest(inputText.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static String hash(final String inputText, final byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(DEFAULT_HASHTYPE.toString());
        md.update(salt);
        byte[] bytes = md.digest(inputText.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static String hash(final String inputText) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(DEFAULT_HASHTYPE.toString());
        byte[] bytes = md.digest(inputText.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    /*----------------------------------------------------------------------------------------------------------------*/

    public static byte[] salt() throws NoSuchProviderException, NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(SHA_SALT_ALGORITHM, SHA_SALT_PROVIDER);
        final byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

}
