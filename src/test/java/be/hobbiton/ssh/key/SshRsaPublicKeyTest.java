package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import be.hobbiton.ssh.key.SshRsaPublicKey.SshRsaPublicKeyException;

public class SshRsaPublicKeyTest {
	private static final String[] KEY_PARTS = SSH_RSA_2048_PUBLIC_KEY.split(" ");


	@Test
	public void testReadRsa2048PublicKey() throws SshRsaPublicKeyException {
		SshRsaPublicKey rsaPublicKey = new SshRsaPublicKey(SSH_RSA_2048_PUBLIC_KEY);
		assertEquals(SSH_RSA_2048_PUBLIC_EXPONENT, rsaPublicKey.getPublicExponent());
		assertEquals(SSH_RSA_2048_PUBLIC_MODULUS, rsaPublicKey.getModulus());
		assertEquals(SSH_RSA_2048_LENGTH, rsaPublicKey.getModulus().bitLength());
		assertEquals("RSA", rsaPublicKey.getAlgorithm());
		assertEquals("X.509", rsaPublicKey.getFormat());
		assertEquals(279, rsaPublicKey.getEncoded().length);
	}

	@Test(expected = SshRsaPublicKeyException.class)
	public void testConstructWrongKeyFormat() throws SshRsaPublicKeyException {
		new SshRsaPublicKey(SSH_DSA_PUBLIC_KEY);
	}

	@Test(expected = SshRsaPublicKeyException.class)
	public void testConstructBadContents() throws SshRsaPublicKeyException {
		new SshRsaPublicKey(KEY_PARTS[0] + " " + KEY_PARTS[1]);
	}

	@Test(expected = SshRsaPublicKeyException.class)
	public void testConstructEmpty() throws SshRsaPublicKeyException {
		new SshRsaPublicKey("");
	}

	@Test(expected = SshRsaPublicKeyException.class)
	public void testConstructNull() throws SshRsaPublicKeyException {
		new SshRsaPublicKey(null);
	}
}
