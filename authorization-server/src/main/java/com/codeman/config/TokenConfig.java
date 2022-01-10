package com.codeman.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author hdgaadd
 * Created on 2022/01/10
 */
@Configuration
public class TokenConfig {
    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }
}
