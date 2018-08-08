package com.example.telco.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class OAuth2Server extends AuthorizationServerConfigurerAdapter {

    @Value("${spring.security.oauth2.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client-secret}")
    private String clientPassword;


    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    /**
     * basic encryptor
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("123");//TODO - upgrade to external signature local key
        return converter;
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());//calls the JWT piece here
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

    /**
     * looks at how to enhance a token, convert and manage it
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
//        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter())); //commented out because we're not "manually" enhancing it
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter()));
        endpoints.tokenStore(tokenStore()).tokenEnhancer(tokenEnhancerChain).authenticationManager(authenticationManager);
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    /**
     * sets a single token scenario with permissions and timeouts
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient(clientId)
                .secret(passwordEncoder().encode(clientPassword))
                .authorizedGrantTypes("password", "authorization_code", "refresh_token")
                .scopes("read", "write")
                .accessTokenValiditySeconds(3600)
                // 1 hour
                .refreshTokenValiditySeconds(2592000);
    }
}
