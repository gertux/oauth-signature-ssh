package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import org.junit.Test;

import be.hobbiton.ssh.key.SshPublicKey.SshPublicKeyException;

public class SshRsaPublicKeyTest {
	private static final String[] KEY_PARTS = SSH_RSA_2048_PUBLIC_KEY.split(" ");

	@Test
	public void testReadRsa2048PublicKey() throws Exception {
		SshRsaPublicKey rsaPublicKey = new SshRsaPublicKey(SSH_RSA_2048_PUBLIC_KEY);
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPublicKey.getPublicExponent());
		assertEquals(SSH_RSA_2048_MODULUS, rsaPublicKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPublicKey.getModulus().bitLength());
		assertEquals("RSA", rsaPublicKey.getAlgorithm());
		assertEquals("X.509", rsaPublicKey.getFormat());
		byte[] encoded = rsaPublicKey.getEncoded();
		assertEquals(279, encoded.length);
		byte[] encodedAgain = rsaPublicKey.getEncoded();
		assertArrayEquals(encoded, encodedAgain);
		assertNotEquals(encoded, encodedAgain);
	}

	@Test
	public void testReadRsa768PublicKey() throws Exception {
		SshRsaPublicKey rsaPublicKey = new SshRsaPublicKey(SSH_RSA_768_PUBLIC_KEY);
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPublicKey.getPublicExponent());
		assertEquals(SSH_RSA_768_MODULUS, rsaPublicKey.getModulus());
		assertEquals(SSH_RSA_768_LENGTH, rsaPublicKey.getModulus().bitLength());
		assertEquals("RSA", rsaPublicKey.getAlgorithm());
		assertEquals("X.509", rsaPublicKey.getFormat());
		assertEquals(119, rsaPublicKey.getEncoded().length);
	}

	@Test
	public void testReadRsa4096PublicKey() throws Exception {
		SshRsaPublicKey rsaPublicKey = new SshRsaPublicKey(SSH_RSA_4096_PUBLIC_KEY);
		assertEquals(SSH_RSA_PUBLIC_EXPONENT, rsaPublicKey.getPublicExponent());
		assertEquals(SSH_RSA_4096_MODULUS, rsaPublicKey.getModulus());
		assertEquals(SSH_RSA_4096_LENGTH, rsaPublicKey.getModulus().bitLength());
		assertEquals("RSA", rsaPublicKey.getAlgorithm());
		assertEquals("X.509", rsaPublicKey.getFormat());
		assertEquals(535, rsaPublicKey.getEncoded().length);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructWrongKeyFormat() throws Exception {
		new SshRsaPublicKey(SSH_DSA_PUBLIC_KEY);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructBadContents() throws Exception {
		new SshRsaPublicKey(KEY_PARTS[0] + " " + KEY_PARTS[1]);
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructEmpty() throws Exception {
		new SshRsaPublicKey("");
	}

	@Test(expected = SshPublicKeyException.class)
	public void testConstructNull() throws Exception {
		new SshRsaPublicKey(null);
	}
}
