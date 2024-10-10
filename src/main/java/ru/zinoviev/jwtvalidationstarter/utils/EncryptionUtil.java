package ru.zinoviev.jwtvalidationstarter.utils;

public class EncryptionUtil {
    // PKCS#8 format
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    // Public Key Format
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    // Error Message
    public static final String INVALID_PRIVATE_KEY = "Invalid Private Key!!!";
    public static final String RSA = "RSA";
    public static final String PUBLIC_KEY = "*PUBLIC*";
    public static final String PRIVATE_KEY = "PRIVATE";

}
