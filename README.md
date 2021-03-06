# Jersey OAuth 1 signature extension for SSH keys

With this extension to Jersey OAuth 1, one can use her SSH RSA or DSA keys to sign and verify her requests

The current implementation is mainly tested with [Jersey 1.16](https://jersey.java.net/documentation/1.16/index.html) because that's the version I'm using. The latest 1.x Jersey version is also tested, version 1.18.3 currently.

## Maven

When using maven as build system, the dependency is:
```xml
<dependency>
	<groupId>be.hobbiton.jersey</groupId>
	<artifactId>oauth-signature-ssh</artifactId>
	<version>1.0.1</version>
</dependency>
```
	
The artifacts are published in [Maven Central](http://search.maven.org/#search|ga|1|g%3A%22be.hobbiton.jersey%22%20a%3A%22oauth-signature-ssh%22)

## Usage

If the JAR file is included on the classpath the SSH RSA OAuth Signature extension should be auto detected. Just use SSH-RSA as the signature method as in:

```java
OAuthParameters params = new OAuthParameters()
		.verifier(verifier)
		.consumerKey("consumer")
		.token(requestToken)
		.signatureMethod(SSH_RSA.NAME)
		.timestamp()
		.nonce()
		.version();
```

For SSH DSA keys use SSH_DSA.NAME.
