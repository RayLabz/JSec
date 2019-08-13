package com.panickapps.javasecurity;

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
