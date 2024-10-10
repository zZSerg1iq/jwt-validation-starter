package ru.zinoviev.jwtvalidationstarter.service;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.UUID;

public interface JwtService {

    UUID getUserId(String exchange);

    @Deprecated
    DecodedJWT verifyToken(String token);
}
