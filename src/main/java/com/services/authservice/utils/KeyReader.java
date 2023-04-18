package com.services.authservice.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class KeyReader {

  private final ResourceLoader resourceLoader;

  public RSAPrivateKey loadPrivateKey(String privateKeyPath) {
    try {
      String privateKeyContent = readKeyFile(privateKeyPath);
      privateKeyContent = removeKeyHeaders(privateKeyContent);
      byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException("Could not load private key", e);
    }
  }

  public RSAPublicKey loadPublicKey(String publicKeyPath) {
    try {
      String publicKeyContent = readKeyFile(publicKeyPath);
      publicKeyContent = removeKeyHeaders(publicKeyContent);
      byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);

      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException("Could not load public key.", e);
    }
  }

  private String readKeyFile(String filePath) throws IOException {
    Resource resource = resourceLoader.getResource(filePath);
    byte[] fileBytes = FileCopyUtils.copyToByteArray(resource.getInputStream());
    return new String(fileBytes);
  }

  private String removeKeyHeaders(String keyContent) {
    return keyContent
        .replaceAll("-----BEGIN (.*)-----", "")
        .replaceAll("-----END (.*)-----", "")
        .replaceAll("\r\n", "")
        .replaceAll("\n", "");
  }
}
