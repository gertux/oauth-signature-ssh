package be.hobbiton.ssh.key;

import java.math.BigInteger;
import java.util.Arrays;


public class SshBufferStream {
	private byte[] bytes;
	private int pos;
	public SshBufferStream(byte[] bytes) {
		super();
		if ((bytes == null) || (bytes.length < 1)) {
			throw new SshBufferException("Content should not be empty");
		}
		this.bytes = bytes;
		this.pos = 0;
	}

	public String readString() {
		return new String(readBytes());
	}

	public BigInteger readInteger() {
		return new BigInteger(readBytes());
	}

	private byte[] readBytes() {
		int length = readInt();
		if ((this.pos + length) > this.bytes.length) {
			throw new SshBufferOutOfBoundsException("Unexpected end of buffer");
		}
		byte[] value = Arrays.copyOfRange(this.bytes, this.pos, this.pos + length);
		this.pos += length;
		return value;
	}

	private int readInt() {
		if ((this.pos + 4) > this.bytes.length) {
			throw new SshBufferOutOfBoundsException("Unexpected end of buffer");
		}
		int intValue = ((this.bytes[this.pos] << 24) + (this.bytes[this.pos + 1] << 16) + (this.bytes[this.pos + 2] << 8) + this.bytes[this.pos + 3]);
		this.pos += 4;
		return intValue;
	}

	public static class SshBufferException extends RuntimeException {
		private static final long serialVersionUID = 2544140873588046850L;

		public SshBufferException(String message) {
			super(message);
		}
	}

	public static class SshBufferOutOfBoundsException extends RuntimeException {
		private static final long serialVersionUID = 2544140873588046850L;

		public SshBufferOutOfBoundsException(String message) {
			super(message);
		}
	}
}