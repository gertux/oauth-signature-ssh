package be.hobbiton.ssh.key;

import static be.hobbiton.jersey.oauth.signature.ExampleKeys.*;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

import be.hobbiton.ssh.key.SshDsaPrivateKey.SshDsaPrivateKeyException;

public class SshDsaPrivateKeyTest {
	@Test
	public void testReadDsaPrivateKey() throws SshDsaPrivateKeyException {
		SshDsaPrivateKey dsaPrivateKey = new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY);
		assertEquals(SSH_DSA_MODULUS, dsaPrivateKey.getParams().getP());
		assertEquals(SSH_DSA_DIVISOR, dsaPrivateKey.getParams().getQ());
		assertEquals(SSH_DSA_GENERATOR, dsaPrivateKey.getParams().getG());
		assertEquals(SSH_DSA_PRIVATE_EXPONENT, dsaPrivateKey.getX());
		assertEquals(SSH_DSA_PUBLIC_EXPONENT, dsaPrivateKey.getY());
		assertEquals(BigInteger.ZERO, dsaPrivateKey.getVersion());
		assertEquals("DSA", dsaPrivateKey.getAlgorithm());
		assertEquals("PKCS#8", dsaPrivateKey.getFormat());
		assertEquals(448, dsaPrivateKey.getEncoded().length);
	}

	@Test(expected = SshDsaPrivateKeyException.class)
	public void testASNException() throws SshDsaPrivateKeyException {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_HEADER + "AgMPDw8=\n" + SSH_DSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshDsaPrivateKeyException.class)
	public void testMissingHeader() throws SshDsaPrivateKeyException {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_BODY + SSH_DSA_PRIVATE_KEY_FOOTER);
	}

	@Test(expected = SshDsaPrivateKeyException.class)
	public void testMissingFooter() throws SshDsaPrivateKeyException {
		new SshDsaPrivateKey(SSH_DSA_PRIVATE_KEY_HEADER + SSH_DSA_PRIVATE_KEY_BODY);
	}

}
