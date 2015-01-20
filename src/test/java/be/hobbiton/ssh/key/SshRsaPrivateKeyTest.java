package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.SshPrivateKey.SshPrivateKeyException;

public class SshRsaPrivateKeyTest {

	@Test
	public void testReadRsa2048PrivateKey() throws Exception {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY);
		assertEquals(SSH_RSA_2048_MODULUS, SSH_RSA_2048_MODULUS_0X);
		assertEquals(SSH_RSA_2048_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_2048_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		byte[] encoded = rsaPrivateKey.getEncoded();
		assertEquals(1193, encoded.length);
		byte[] encodedAgain = rsaPrivateKey.getEncoded();
		assertArrayEquals(encoded, encodedAgain);
		assertNotEquals(encoded, encodedAgain);
	}

	@Test
	public void testReadRsa2048PrivateKeyCrLf() throws Exception {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY.replaceAll("\n", "\r\n"));
		assertEquals(SSH_RSA_2048_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_2048_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		assertEquals(1193, rsaPrivateKey.getEncoded().length);
	}

	@Test
	public void testReadRsa768PrivateKey() throws Exception {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_768_PRIVATE_KEY);
		assertEquals(SSH_RSA_768_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_768_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_768_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		assertEquals(461, rsaPrivateKey.getEncoded().length);
	}

	@Test
	public void testReadRsa4096PrivateKey() throws Exception {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_4096_PRIVATE_KEY);
		assertEquals(SSH_RSA_4096_MODULUS, SSH_RSA_4096_MODULUS_0X);
		assertEquals(SSH_RSA_4096_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_4096_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_4096_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		assertEquals(2349, rsaPrivateKey.getEncoded().length);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testASNException() throws Exception {
		new SshRsaPrivateKey(SSH_RSA_PRIVATE_KEY_HEADER + "AgMPDw8=\n" + SSH_RSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testMissingHeader() throws Exception {
		new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY_BODY + SSH_RSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testMissingFooter() throws Exception {
		new SshRsaPrivateKey(SSH_RSA_PRIVATE_KEY_HEADER + SSH_RSA_2048_PRIVATE_KEY_BODY);
	}

}
