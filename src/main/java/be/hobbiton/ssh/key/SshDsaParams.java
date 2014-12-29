package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

public class SshDsaParams implements DSAParams {
	private BigInteger p;
	private BigInteger q;
	private BigInteger g;

	public SshDsaParams(BigInteger p, BigInteger q, BigInteger g) {
		super();
		this.p = p;
		this.q = q;
		this.g = g;
	}

	@Override
	public BigInteger getP() {
		return this.p;
	}

	@Override
	public BigInteger getQ() {
		return this.q;
	}

	@Override
	public BigInteger getG() {
		return this.g;
	}
}
