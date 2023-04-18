package com.services.authservice.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

class GenerateKeyPair {

  public static void main(String[] args) {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    Base64.Encoder encoder = Base64.getEncoder();
    System.out.println("-----BEGIN PUBLIC KEY-----\n" + encoder.encodeToString(publicKey.getEncoded()) + "\n" +
        "-----END PUBLIC KEY-----");
    System.out.println("-----BEGIN PRIVATE KEY-----\n" + encoder.encodeToString(privateKey.getEncoded()) + "\n" +
        "-----END PRIVATE KEY-----");
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }
}
