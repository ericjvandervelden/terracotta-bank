package com.joshcummings.codeplay.terracotta.repo;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.joshcummings.codeplay.terracotta.crypto.KeyStore;

public class KeyFactoryKeyRepository implements KeyRepository{
	
	private final String name="keystore.p12";
	private final char[] password="password".toCharArray();

	@Override
	public void store(String alias, SecretKey key) {
		doWithKeyStore(keyStore->{
			keyStore.setKeyEntry(alias, key, password, null);
			return null;
		});
	}

	@Override
	public void store(String alias, KeyPair pair) {
		doWithKeyStore(keyStore->{
			keyStore.setKeyEntry(alias, pair.getPrivate(), password, null);
			// het laatste arg moet certificates zijn, niet null,
		// daarom loopt de KeyServiceTest fout met deze repo,
			return null;
		});
		
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends Key> T load(String alias) {
		return doWithKeyStore(keyStore->
			(T) keyStore.getKey(alias, password));
	}
	
//	@Override
//	public <T extends Key> T load(String alias) {
//		return doWithKeyStore(keyStore->{
//			(T) keyStore.getKey(alias, password);});
//	}
// ERR, TODO
	
	private <T> T doWithKeyStore(Function<KeyStore, T> c) { // copy van KeyStoreKeyRepository,
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(this.name)) {
			keyStore.load(fis, this.password);	// Loads this KeyStore from the given input stream.
			// keyStore bevat nu de hele keystore,
			return c.apply(keyStore); // apply c op inderdaad de (hele) keystore,
		} catch (IOException e) {
			throw new IllegalStateException(e);
		} finally {	// als c een store heeft gedaan, dan wil je die wegschrijven,
			try (FileOutputStream fos = new FileOutputStream(this.name)) {
				keyStore.store(fos, this.password);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}
	}

}
