package ru.zinoviev.jwtvalidationstarter.excepton;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class TokenVerifyException extends RuntimeException {

    public TokenVerifyException(String message) {
        super(message);
    }
}
