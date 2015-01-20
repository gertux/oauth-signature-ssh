package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.SshPrivateKey.SshPrivateKeyException;

public class SshDsaPrivateKeyTest {
	@Test
	public void testReadDsaPrivateKey() throws Exception {
		SshDsaPrivateKey dsaPrivateKey = new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY);
		assertEquals(SSH_DSA_MODULUS, dsaPrivateKey.getParams().getP());
		assertEquals(SSH_DSA_DIVISOR, dsaPrivateKey.getParams().getQ());
		assertEquals(SSH_DSA_GENERATOR, dsaPrivateKey.getParams().getG());
		assertEquals(SSH_DSA_PRIVATE_EXPONENT, dsaPrivateKey.getX());
		assertEquals(SSH_DSA_PUBLIC_EXPONENT, dsaPrivateKey.getY());
		assertEquals(BigInteger.ZERO, dsaPrivateKey.getVersion());
		assertEquals("DSA", dsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", dsaPrivateKey.getFormat());
		byte[] encoded = dsaPrivateKey.getEncoded();
		assertEquals(448, encoded.length);
		byte[] encodedAgain = dsaPrivateKey.getEncoded();
		assertArrayEquals(encoded, encodedAgain);
		assertNotEquals(encoded, encodedAgain);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testASNException() throws Exception {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_HEADER + "AgMPDw8=\n" + SSH_DSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testMissingHeader() throws Exception {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_BODY + SSH_DSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshPrivateKeyException.class)
	public void testMissingFooter() throws Exception {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_HEADER + SSH_DSA_PRIVATE_KEY_BODY);
	}

}
