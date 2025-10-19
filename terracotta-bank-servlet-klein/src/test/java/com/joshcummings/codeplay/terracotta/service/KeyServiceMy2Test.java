package com.joshcummings.codeplay.terracotta.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.joshcummings.codeplay.terracotta.crypto.KeyFactory;
import com.joshcummings.codeplay.terracotta.repo.InMemoryKeyRepository;
import com.joshcummings.codeplay.terracotta.repo.KeyFactoryKeyRepository;

//import static org.testng.Assert.assertEquals;
//import static org.testng.Assert.assertNotNull;

/**
 * Note the docker command to start vault with the appropriate dev settings:
 *
 * <pre>
 *     docker run --name=dev-vault --cap-add=IPC_LOCK -p 8200:8200 -d vault
 * </pre>
 */

// omdat we new KeyFactoryKeyRepository doen ipv. new KeyStoreKeyRepository krijgen we,
/*
 * java.lang.IllegalArgumentException: Private key must be accompanied by certificate chain
	at java.base/java.security.KeyStore.setKeyEntry(KeyStore.java:1163)
	at com.joshcummings.codeplay.terracotta.crypto.KeyStore.setKeyEntry(KeyStore.java:66)
	at com.joshcummings.codeplay.terracotta.repo.KeyFactoryKeyRepository.lambda$1(KeyFactoryKeyRepository.java:31)
	at com.joshcummings.codeplay.terracotta.repo.KeyFactoryKeyRepository.doWithKeyStore(KeyFactoryKeyRepository.java:55)
	at com.joshcummings.codeplay.terracotta.repo.KeyFactoryKeyRepository.store(KeyFactoryKeyRepository.java:30)
	at com.joshcummings.codeplay.terracotta.service.KeyService.generateAsymmetric(KeyService.java:37)
	at com.joshcummings.codeplay.terracotta.service.KeyServiceMyTest.testAsymmetricGenerateAndLoadRoundtrip(KeyServiceMyTest.java:54)
 */



public class KeyServiceMy2Test {
	private KeyService keyService;

//	@BeforeMethod
	@BeforeEach
	public void setUp() {
		keyService = new KeyService(new InMemoryKeyRepository());
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
