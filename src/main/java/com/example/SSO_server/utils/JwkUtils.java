package com.example.SSO_server.utils;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


//Создаем RSA JWK
public class JwkUtils {

//  Возвращает JWK
    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey =  (RSAPrivateKey) keyPair.getPrivate();

//      возвращем jwk
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try{
//          указывает тип парных ключей - RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//          указываем рамер ключа
            keyPairGenerator.initialize(2048);
//          генерируем пару ключей
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch(Exception e){
            throw new IllegalStateException(e);
        }
        return keyPair;
    }
}
