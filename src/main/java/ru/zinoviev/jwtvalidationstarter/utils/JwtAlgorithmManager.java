package ru.zinoviev.jwtvalidationstarter.utils;

import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@AllArgsConstructor
public class JwtAlgorithmManager {
    private final String rsaPublicKey;
    private final String rsaPrivateKey;


    public Algorithm getTokenAlgorithm() {
        try {
            RsaUtil rsaUtil = new RsaUtil();

            RSAPublicKey publicKey = null;
            if (this.rsaPublicKey != null) {
                publicKey = (RSAPublicKey) rsaUtil.getPublicKey(this.rsaPublicKey);
            }

            RSAPrivateKey privateKey = null;
            if (this.rsaPrivateKey != null) {
                privateKey = (RSAPrivateKey) rsaUtil.getPrivateKey(this.rsaPrivateKey);
            }

            return Algorithm.RSA512(publicKey, privateKey);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }
}
