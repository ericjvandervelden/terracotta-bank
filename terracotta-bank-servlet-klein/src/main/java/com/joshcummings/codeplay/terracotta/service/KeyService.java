package com.joshcummings.codeplay.terracotta.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.SecretKey;

import com.joshcummings.codeplay.terracotta.crypto.KeyFactory;
import com.joshcummings.codeplay.terracotta.crypto.KeyGenerator;
import com.joshcummings.codeplay.terracotta.crypto.KeyPairGenerator;
import com.joshcummings.codeplay.terracotta.repo.KeyRepository;

public class KeyService {
	
	private final KeyRepository repo;

	public KeyService(KeyRepository keyRepository) {
		this.repo = keyRepository;
	}
	
	public void generateSymmetric(String alias) {
		KeyGenerator g = KeyGenerator.getInstance("AES");
		g.init(256);
		repo.store(alias, g.generateKey());	// is een spec, SecretKeySpec, en een SecretKey,
	}
	
	public SecretKey exportSymmetric(String alias) {
		return repo.load(alias);
	}
	
	public void generateAsymmetric(String alias) {
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.init(2048);
		repo.store(alias, g.generateKeyPair());
	}
	
	// gegeven een priv, maak een keypair 
	public KeyPair exportAsymmetric(String alias) {
		PrivateKey priv = repo.load(alias);	// sun.security.rsa.RSAPrivateCrtKeyImpl
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPrivateCrtKeySpec privSpec = fact.getKeySpec(priv, RSAPrivateCrtKeySpec.class);
				// dit deed InMemoryKeyRepository.store ook,
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(privSpec.getModulus(), privSpec.getPublicExponent());
		PublicKey pub = fact.generatePublic(pubSpec);
		return new KeyPair(pub, priv);
		
	}
	

}
