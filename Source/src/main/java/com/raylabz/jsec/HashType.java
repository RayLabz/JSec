package com.raylabz.jsec;

/**
 * Created by RayLabz - 2019
 * Visit http://www.RayLabz.com
 *
 * Java Security Essentials - A simple encryption and hashing library for Java.
 * Provides methods for hashing, symmetric and asymmetric encryption.
 * Repository: https://github.com/RayLabz/java-security-essentials
 * Guide: https://RayLabz.github.io/Java-Security-Essentials/
 *
 * Apache 2.0 License
 */

/**
 * Defines the hashing algorithms that can be used in hashing methods.
 */
public enum HashType {

    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512")

    ;

    private final String text;

    HashType(String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }

}
