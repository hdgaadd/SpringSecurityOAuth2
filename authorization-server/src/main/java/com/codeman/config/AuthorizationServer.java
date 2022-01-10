package com.codeman.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author hdgaadd
 * Created on 2022/01/10
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager; // [ɔːˌθentɪˈkeɪʃn]证实

    /**
     * 配置**可访问**授权服务器的**客户端**的各项信息
     * @param clients
     * @throws Exception
     */
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory() // [ˈmeməri]记忆
            .withClient("c1")
            .secret(new BCryptPasswordEncoder().encode("secret")) // [ˈsiːkrət]秘密
            .resourceIds("res1")
            .authorizedGrantTypes("authorization_code",
                    "password","client_credentials","implicit","refresh_token") // 设置可访问的客户端类型
            .scopes("all")
            .autoApprove(false) // [əˈpruːv]同意
            .redirectUris("http://www.baidu.com");
    }

    /**
     * 配置访问授权服务器的url，即访问端点
     * @param endpoints
     * @throws Exception
     */
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .authorizationCodeServices(authorizationCodeServices)
                .tokenServices(tokenServices()) // 配置发放令牌的形式、配置令牌的有效期
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    /**
     * 访问端点的安全策略
     * @param security
     * @throws Exception
     */
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll")
                .checkTokenAccess("permitAll")
                .allowFormAuthenticationForClients();
    }

    /**
     * 配置发放令牌的形式、配置令牌的有效期
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices service = new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService);
        service.setSupportRefreshToken(false);
        service.setTokenStore(tokenStore);
        service.setAccessTokenValiditySeconds(3600); // token有效期
        service.setRefreshTokenValiditySeconds(3600); // 刷新令牌有效期
        return service;
    }

    /**
     * 设置授权码的存储方式，使用内存存储
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }

}
