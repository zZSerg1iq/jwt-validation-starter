package ru.zinoviev.jwtvalidationstarter.config;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import ru.zinoviev.jwtvalidationstarter.service.impl.JwtServiceImpl;
import ru.zinoviev.jwtvalidationstarter.utils.EncryptionUtil;
import ru.zinoviev.jwtvalidationstarter.utils.JwtAlgorithmManager;


@ConditionalOnProperty(prefix = "global.exceptions", name = "enabled", matchIfMissing = true)
public class JwtValidationAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(Algorithm.class)
    public Algorithm getTokenAlgorithm() {
        JwtAlgorithmManager jwtAlgorithmManager = new JwtAlgorithmManager(EncryptionUtil.PUBLIC_KEY, EncryptionUtil.PRIVATE_KEY);
        return jwtAlgorithmManager.getTokenAlgorithm();
    }

    @Bean
    @ConditionalOnMissingBean(JwtServiceImpl.class)
    public JwtServiceImpl getJwtServiceImpl(Algorithm algorithm) {
        return new JwtServiceImpl(algorithm);
    }

}
