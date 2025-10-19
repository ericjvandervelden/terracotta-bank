package my;



import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

public class Scratch {
	
	// voor alle keys, symm, asymm geldt dat KeyGenerator altijd werkt, geeft keys,
	// ook voor AES, maar je krijgt een SecretKeySpec, bij DES een DESKey, TODO
	// met KeyFactory kun je specs maken, en vanuit de specs ook weer de keys maken,
	// niet voor AES, TODO, maar je krijgt de spec met de KeyGenerator!, en die is ook 
	// de SecretKey,
	
	// met een PrivateKey, of SecretKey heb je .getEncoded(), getAlgorithm(), ...
	// met een RSAPrivateKeySpec kun je .getModulus(), .getPrivateComponent(), geen .getEncode(), 
	// met een RSAPrivateCrtKeySpec kun je ook .getPrimeP(), ..., maar dat kun je ook met een RSAPrivateCrtKey,
	// dus als je een PrivateKey hebt via KeyPairGenerator, dan na cast met RSAPrivateCrtKey kun je alle methods doen die RSAPrivateCrtKeySpec geeft, 
	// dus daar hoef je geen spec voor te maken via een KeyFactory, 
	// met SecretKey of SecretKeySpec kun je getEncoded(), en dat is WH voldoende voor een symm key,
	
	
	// deze test hebben we zelf verzonnen, nav KeyService en InMemoryKeyRepository
	@Test
	public void test() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2028);
		KeyPair pair = pairGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();	// sun.security.rsa.RSAPrivateCrtKeyImpl
		PublicKey pub = pair.getPublic();		// sun.security.rsa.RSAPublicKeyImpl
		BigInteger primeExponentP = ((RSAPrivateCrtKey)priv).getPrimeExponentP();
		// dit kan dus!
		System.out.println(primeExponentP);
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPrivateCrtKeySpec privSpec = fact.getKeySpec(priv, RSAPrivateCrtKeySpec.class);
		RSAPrivateKeySpec privSpec2 = fact.getKeySpec(priv, RSAPrivateKeySpec.class);
		System.out.println(privSpec.getClass());	// java.security.spec.RSAPrivateCrtKeySpec
		System.out.println(privSpec2.getClass());	// java.security.spec.RSAPrivateCrtKeySpec
		RSAPrivateCrtKeySpec privSpec1=(RSAPrivateCrtKeySpec)privSpec2;
		// https://stackoverflow.com/questions/12147297/how-do-i-assert-equality-on-two-classes-without-an-equals-method
//		assertThat(privSpec1).usingRecursiveComparison().isEqualTo(privSpec); 
													// slaagt niet, TODO
		assertThat(privSpec1).isEqualToComparingFieldByFieldRecursively(privSpec); // slaagt,
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(privSpec.getModulus(), privSpec.getPublicExponent());
		PublicKey pub1 = fact.generatePublic(pubSpec);
		assertThat(pub1).isEqualTo(pub);		// dus je hebt hem al hierboven, dus de privSpec maken en daaruit -> pub? TODO
		KeyPair pair1 = new KeyPair(pub1, priv);
//		assertThat(pair1).usingRecursiveComparison().isEqualTo(pair);		// slaagt niet,
// 		assertThat(pair1).isEqualToComparingFieldByFieldRecursively(pair);	// slaagt niet; KeyPair heeft geen getPrivateKey()
		boolean b=false;
		
		
		
	}
	
	// video ch3, a simple key service
	@Test
	public void test2() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPair pair=KeyPairGenerator.getInstance("RSA").generateKeyPair();
		PrivateKey priv=pair.getPrivate();	// een sun.security.rsa.RSAPrivateCrtKeyImpl
		RSAPrivateCrtKey privCrt = (RSAPrivateCrtKey)pair.getPrivate();		// heeft alle methods,
		priv.getEncoded();
		privCrt.getPrimeExponentP();
		
		// dus door te cast naar RSAPrivateCrtKey heb je ineens alle methods, is compile time type,
		
		// we hoeven alleen m,d op te slaan, en we kunnen herleiden een sun.security.rsa.RSAPrivateKeyImpl
		KeyFactory fact  = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec privSpec = fact.getKeySpec(priv, RSAPrivateKeySpec.class);
		System.out.println(privSpec.getClass());// java.security.spec.RSAPrivateCrtKeySpec
		// maar de compile time type is RSAPrivateKeySpec, en geen RSAPrivateCrtKeySpec
		BigInteger m = privSpec.getModulus();
		BigInteger d = privSpec.getPrivateExponent();
		RSAPrivateKeySpec privSpec2 = new RSAPrivateKeySpec(m, d);
		PrivateKey priv1 = fact.generatePrivate(privSpec2);	
			// sun.security.rsa.RSAPrivateKeyImpl, heeft alleen .getEncoded() der encoding, getAlgorithm(), ...
			// kun je niet cast naar RSAPrivateCrtKey,
		System.out.println(priv1.getClass());	// sun.security.rsa.RSAPrivateKeyImpl
		
		// we hoeven alleen m,e,d,p,q,ep,eq,c op te slaan, en we kunnen herleiden een sun.security.rsa.RSAPrivateCrtKeyImpl
		RSAPrivateCrtKeySpec privCrtSpec = fact.getKeySpec(priv, RSAPrivateCrtKeySpec.class);
		BigInteger m_ = privCrtSpec.getModulus();
		BigInteger e = privCrtSpec.getPublicExponent();
		BigInteger d_ = privCrtSpec.getPrivateExponent();
		BigInteger p = privCrtSpec.getPrimeP();
		BigInteger q = privCrtSpec.getPrimeQ();
		BigInteger ep = privCrtSpec.getPrimeExponentP();
		BigInteger eq = privCrtSpec.getPrimeExponentQ();
		BigInteger c = privCrtSpec.getCrtCoefficient();
		
		RSAPrivateCrtKeySpec privCrtSpec2 = new RSAPrivateCrtKeySpec(m_,e,d_,p,q,ep,eq,c);
		PrivateKey priv2 = fact.generatePrivate(privCrtSpec2);
		System.out.println(priv2.getClass());	// sun.security.rsa.RSAPrivateCrtKeyImpl
		

		
	}
	
	// video ch3, key generators
	@Test
	public void test3() throws NoSuchAlgorithmException {
		Set<String> algorithms = Security.getAlgorithms("KeyGenerator");
		System.out.println(algorithms);
		// [RC2, SUNTLSKEYMATERIAL, HMACSHA384, DESEDE, BLOWFISH, ARCFOUR, HMACSHA512/256, HMACSHA256, HMACSHA224, HMACMD5, HMACSHA512/224, AES, HMACSHA3-384, CHACHA20, SUNTLSPRF, HMACSHA512, SUNTLSRSAPREMASTERSECRET, DES, HMACSHA3-256, HMACSHA3-224, HMACSHA3-512, SUNTLSMASTERSECRET, HMACSHA1, SUNTLS12PRF]
		KeyGenerator aesGen = KeyGenerator.getInstance("AES");
		SecretKey key = aesGen.generateKey();
		
		System.out.println(key.getClass());// javax.crypto.spec.SecretKeySpec
			// je hebt geen KeyFactory nodig, die is er ook niet voor AES
			// bij DES krijg je hier een DESKey, dus geen spec, en daar is wel een KeyFactory,
		key.getEncoded();
		key.getAlgorithm();
		// dit is net als bij de private key in test2(), maar daar is key geen spec, TODO
		int len=key.getEncoded().length*8;
		System.out.println(len);// 128
		
	}
	
	// video ch3, key factories
	@Test
	public void test4() throws NoSuchAlgorithmException, InvalidKeySpecException {
		Set<String> algorithms = Security.getAlgorithms("SecretKeyFactory");
		System.out.println(algorithms);
		// [PBEWITHHMACSHA384ANDAES_128, PBEWITHSHA1ANDRC4_40, PBEWITHHMACSHA512ANDAES_256, DESEDE, PBEWITHHMACSHA512ANDAES_128, PBKDF2WITHHMACSHA1, PBKDF2WITHHMACSHA384, PBEWITHHMACSHA224ANDAES_256, DES, PBEWITHHMACSHA256ANDAES_128, PBEWITHMD5ANDDES, PBEWITHHMACSHA256ANDAES_256, PBKDF2WITHHMACSHA224, PBEWITHHMACSHA1ANDAES_128, PBEWITHSHA1ANDRC4_128, PBEWITHSHA1ANDDESEDE, PBKDF2WITHHMACSHA512, PBEWITHSHA1ANDRC2_128, PBEWITHSHA1ANDRC2_40, PBEWITHHMACSHA384ANDAES_256, PBEWITHHMACSHA1ANDAES_256, PBEWITHMD5ANDTRIPLEDES, PBEWITHHMACSHA224ANDAES_128, PBKDF2WITHHMACSHA256]
		
		KeyGenerator desGen = KeyGenerator.getInstance("DES");	// AES kan ook, zie test3(),
		SecretKey desKey = desGen.generateKey();
		System.out.println(desKey.getClass());// com.sun.crypto.provider.DESKey
			// bij AES was dit een SecretKeySpec, TODO
		desKey.getAlgorithm();
		desKey.getEncoded();
		SecretKeyFactory desFact = SecretKeyFactory.getInstance("DES");// AES kan niet,
		KeySpec desKeySpec = desFact.getKeySpec(desKey, DESKeySpec.class);
		System.out.println(desKeySpec);// javax.crypto.spec.DESKeySpec@41e1e210
		SecretKey desKey2 = desFact.generateSecret(desKeySpec);
		assertThat(desKey2).isEqualTo(desKey);
		
	}

}
