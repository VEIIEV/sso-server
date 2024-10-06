package com.example.SSO_server.configs;

import com.example.SSO_server.utils.JwkUtils;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;

@Configuration
@EnableConfigurationProperties(AuthorizationServerProperties.class)
public class AuthorizationServerConfig {

    private final AuthorizationServerProperties authorizationServerProperties;

    @Autowired
    public AuthorizationServerConfig(AuthorizationServerProperties authorizationServerProperties) {
        this.authorizationServerProperties = authorizationServerProperties;
    }


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );
        return http.build();
    }



//   возвращает репозитори из которого можно извелечь клиентов, зарегестрированных в системе
//   как юзер details, но для клиентов (приложений) которые к нему обращаются
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
                RegisteredClient.withId("test-client-id")
                        .clientName("Test Client")
                        .clientId("test-client")
                        .clientSecret("{noop}test-client")
//                        .redirectUri("http://localhost:8080/code")
                        .redirectUri("http://localhost:8080/login/oauth2/code/client-oidc")
//параметр redirectUri, он необходим для типа аутентификации authorization code flow,
// то есть для grant_type AUTHORIZATION_CODE.
// В этом параметре мы указываем, на какой URL разрешен редирект
// после успешной аутентификации пользователя.
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//В методе аутентификации установим Basic Authentication - это значит,
// чтобы пройти аутентификацию клиента, нам необходимо указать Authorization хедер с типом Basic
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .build()
        );

    }

//описание конфигурации хранилища RSA ключей
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = JwkUtils.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);

//      return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet)

        return new JWKSource<>() {

            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return jwkSelector.select(jwkSet);
            }
        };

    }


//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
////               issuer - это корневой URL адрес нашего SSO сервера
//                .issuer(authorizationServerProperties.getIssuer())
//                .build();
//    }


}
