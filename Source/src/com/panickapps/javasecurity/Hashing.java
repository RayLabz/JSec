package com.panickapps.javasecurity;

import java.security.MessageDigest;
import java.security.SecureRandom;

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
 * Provides functionality for hashing using various algorithms.
 */
public class Hashing {

    private static final String SHA_SALT_ALGORITHM = "SHA1PRNG";
    private static final String SHA_SALT_PROVIDER = "SUN";
    private static final HashType DEFAULT_HASHTYPE = HashType.SHA512;

    /**
     * Hashes given data using a given hashing algorithm and salt.
     * @param hashType The hashing algorithm to use.
     * @param data The data to hash.
     * @param salt The salt data to use.
     * @return Returns a string hash.
     */
    public static String hash(final HashType hashType, final byte[] data, final byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashType.toString());
            md.update(salt);
            byte[] bytes = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Hashes given data using a given hashing algorithm.
     * @param hashType The hashing algorithm to use.
     * @param data The data to hash.
     * @return Returns a string hash.
     */
    public static String hash(final HashType hashType, final byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashType.toString());
            byte[] bytes = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Hashes given data using the default hashing algorithm and the given salt.
     * @param data The data to hash.
     * @param salt The salt data to use.
     * @return Returns a string hash.
     */
    public static String hash(final byte[] data, final byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance(DEFAULT_HASHTYPE.toString());
            md.update(salt);
            byte[] bytes = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Hashes given data using the default hashing algorithm.
     * @param data The data to hash.
     * @return Returns a string hash.
     */
    public static String hash(final byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(DEFAULT_HASHTYPE.toString());
            byte[] bytes = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates random salt data.
     * @return Returns a byte array of random data to use as salt.
     */
    public static byte[] salt() {
        try {
            SecureRandom sr = SecureRandom.getInstance(SHA_SALT_ALGORITHM, SHA_SALT_PROVIDER);
            final byte[] salt = new byte[16];
            sr.nextBytes(salt);
            return salt;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
