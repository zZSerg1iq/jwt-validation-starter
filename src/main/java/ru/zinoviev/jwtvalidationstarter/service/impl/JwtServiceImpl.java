package ru.zinoviev.jwtvalidationstarter.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import ru.zinoviev.jwtvalidationstarter.excepton.TokenVerifyException;
import ru.zinoviev.jwtvalidationstarter.service.JwtService;
import ru.zinoviev.jwtvalidationstarter.utils.JwtUtility;

import java.util.UUID;

@Service
@AllArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final Algorithm algorithm;

    @Override
    public UUID getUserId(String token) {
        if (token == null) {
            throw new TokenVerifyException("Токен отсутствует");
        }

        String tokenStartWith = "Bearer ";

        if (token.startsWith(tokenStartWith)) {
            String jwtToken = token.substring(tokenStartWith.length());
            return UUID.fromString(verifyToken(jwtToken).getClaim(JwtUtility.TOKEN_CLAIM_CLIENT_ID).asString());
        }


        throw new TokenVerifyException("Ошибка декодирования токена");
    }

    @Override
    public DecodedJWT verifyToken(String token) {
        try {
            return JWT.require(algorithm)
                    .withIssuer(JwtUtility.TOKEN_ISSUER)
                    .build()
                    .verify(token);
        } catch (SignatureVerificationException
                 | JWTDecodeException
                 | AlgorithmMismatchException
                 | TokenExpiredException
                 | InvalidClaimException exp) {
            throw new TokenVerifyException("Token Verification Failed - " + exp);
        }
    }
}
