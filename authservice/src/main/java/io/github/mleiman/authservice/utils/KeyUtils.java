package io.github.mleiman.authservice.utils;

import com.nimbusds.jose.jwk.RSAKey;
import io.github.mleiman.authservice.exception.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@Slf4j
@Component
public class KeyUtils {
	private static final String KEY_ALGORITHM = "RSA";

	@Value("@{spring.profiles.active}")
	private String activeProfile;
	@Value("@{keys.private}")
	private String privateKey;
	@Value("@{keys.public}")
	private String publicKey;

	public RSAKey getRSAKeyPair() {
		return generateRSAKeyPair(privateKey, publicKey);
	}

	private RSAKey generateRSAKeyPair(String privateKeyName, String publicKeyName) {
		KeyPair keyPair;
		var keysDir = Paths.get("src", "main", "resources", "keys");
		verifyKeysDir(keysDir);
		if(Files.exists(keysDir.resolve(privateKey)) && Files.exists(keysDir.resolve(publicKey))) {
			log.info("RSA keys already exists. Loading keys from file system: \n* {} \n* {}", privateKey, publicKey);
			var privateKeyFile = keysDir.resolve(privateKey).toFile();
			var publicKeyFile = keysDir.resolve(publicKey).toFile();
			try {
				var keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
				byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

				byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
				RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

				var keyId = UUID.randomUUID().toString();
				log.info("Key ID: {}", keyId);

				return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
			} catch (Exception e) {
				log.error(e.getMessage());
				throw new ApiException(e.getMessage());
				//TODO: Separate exceptions and log
			}
		} else {
			if (activeProfile.equalsIgnoreCase("prod")) {
				throw new ApiException("Public and private keys don't exist in prod environment");
			}
		}
		log.info("Generating new RSA keys...\n* {} \n* {}");
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

			try (var fos = new FileOutputStream(keysDir.resolve(publicKeyName).toFile())) {
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
				fos.write(keySpec.getEncoded());
			}

			try (var fos = new FileOutputStream(keysDir.resolve(privateKeyName).toFile())) {
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
				fos.write(keySpec.getEncoded());
			}

			return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();

		} catch (Exception e) {
			throw new ApiException(e.getMessage());
		}
	}

	private void verifyKeysDir(Path keysDir) {
		if (!Files.exists(keysDir)) {
			try {
				Files.createDirectories(keysDir);
			} catch (IOException e) {
				throw new ApiException(e.getMessage());
			}
			log.info("Created keys directory: {}", keysDir);
		}
	}


}
