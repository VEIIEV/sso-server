package com.example.SSO_server.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;


@Getter
@Setter
@ConfigurationProperties("spring.security.oauth2.authorizationserver")
public class AuthorizationServerProperties {


    //  private String issuerUrl; было в примере
    private String issuer;
    private String introspectionEndpoint;


}
