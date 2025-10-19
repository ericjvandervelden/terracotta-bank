package com.joshcummings.codeplay.terracotta.service;

import com.joshcummings.codeplay.terracotta.crypto.KeyFactory;
import com.joshcummings.codeplay.terracotta.repo.KeyStoreKeyRepository;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
//import org.testng.annotations.BeforeMethod;
//import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import java.net.URI;
import java.security.KeyPair;
import java.security.spec.RSAPrivateCrtKeySpec;

//import static org.testng.Assert.assertEquals;
//import static org.testng.Assert.assertNotNull;

/**
 * Note the docker command to start vault with the appropriate dev settings:
 *
 * <pre>
 *     docker run --name=dev-vault --cap-add=IPC_LOCK -p 8200:8200 -d vault
 * </pre>
 */
public class KeyServiceTest {
	private KeyService keyService;

//	@BeforeMethod
	@BeforeEach
	public void setUp() {
		keyService = new KeyService(new KeyStoreKeyRepository());
	}

	@Test
	public void testSymmetricGenerateAndLoadRoundtrip() {
		this.keyService.generateSymmetric("symmetric");
		SecretKey key = keyService.exportSymmetric("symmetric");
		assertThat(key).isNotNull();
//		assertNotNull(key);
		assertThat(key.getAlgorithm()).isEqualTo("AES");
//		assertEquals("AES", key.getAlgorithm());
//		assertEquals(256, 8 * key.getEncoded().length);
		assertThat(8*key.getEncoded().length).isEqualTo(256);
	}

	@Test
	public void testAsymmetricGenerateAndLoadRoundtrip() {
		this.keyService.generateAsymmetric("asymmetric");
		KeyPair pair = this.keyService.exportAsymmetric("asymmetric");
//		assertNotNull(pair);
		assertThat(pair).isNotNull();
//		assertEquals("RSA", pair.getPrivate().getAlgorithm());
		assertThat(pair.getPrivate().getAlgorithm()).isEqualTo("RSA");

		RSAPrivateCrtKeySpec keySpec = KeyFactory.getInstance("RSA")
				.getKeySpec(pair.getPrivate(), RSAPrivateCrtKeySpec.class);
		assertThat(keySpec.getPrimeP().bitLength()).isEqualTo(1024);
//		assertEquals(1024, keySpec.getPrimeP().bitLength());
	}
}
