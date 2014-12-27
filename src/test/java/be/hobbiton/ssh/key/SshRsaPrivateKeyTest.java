package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.SshRsaPrivateKey.SshRsaPrivateKeyException;

public class SshRsaPrivateKeyTest {

	@Test
	public void testReadRsa2048PrivateKey() throws SshRsaPrivateKeyException {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY);
		assertEquals(SSH_RSA_2048_PUBLIC_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_2048_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_2048_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		assertEquals(1193, rsaPrivateKey.getEncoded().length);
	}

	@Test
	public void testReadRsa2048PrivateKeyCrLf() throws SshRsaPrivateKeyException {
		SshRsaPrivateKey rsaPrivateKey = new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY.replaceAll("\n", "\r\n"));
		assertEquals(SSH_RSA_2048_PUBLIC_MODULUS, rsaPrivateKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPrivateKey.getModulus().bitLength());
		assertEquals(SSH_RSA_2048_PRIVATE_EXPONENT, rsaPrivateKey.getPrivateExponent());
		assertEquals(SSH_RSA_2048_PUBLIC_EXPONENT, rsaPrivateKey.getPublicExponent());
		assertEquals(BigInteger.ZERO, rsaPrivateKey.getVersion());
		assertEquals("RSA", rsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", rsaPrivateKey.getFormat());
		assertEquals(1193, rsaPrivateKey.getEncoded().length);
	}

	@Test(expected = SshRsaPrivateKeyException.class)
	public void testASNException() throws SshRsaPrivateKeyException {
		new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY_HEADER + "AgMPDw8=\n" + SSH_RSA_2048_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshRsaPrivateKeyException.class)
	public void testMissingHeader() throws SshRsaPrivateKeyException {
		new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY_BODY + SSH_RSA_2048_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshRsaPrivateKeyException.class)
	public void testMissingFooter() throws SshRsaPrivateKeyException {
		new SshRsaPrivateKey(SSH_RSA_2048_PRIVATE_KEY_HEADER + SSH_RSA_2048_PRIVATE_KEY_BODY);
	}
}
