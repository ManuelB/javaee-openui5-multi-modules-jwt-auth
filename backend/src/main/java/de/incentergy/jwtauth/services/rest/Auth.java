package de.incentergy.jwtauth.services.rest;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.json.Json;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

@Path("/auth")
public class Auth {
	private static final Logger log = Logger.getLogger(Auth.class.getName());
	private X509Certificate certificate;
	private PrivateKey privateKey;

	@PostConstruct
	public void init() {
		try {
			MBeanServerConnection mbeanServerConnection = ManagementFactory.getPlatformMBeanServer();
			ObjectName serverIdentityMBeanName = new ObjectName(
					"jboss.as:core-service=management,security-realm=ApplicationRealm,server-identity=ssl");
			String alias = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName, "alias");
			String keyPassword = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName, "keyPassword");
			String keystorePassword = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName,
					"keystorePassword");
			String keystorePath = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName, "keystorePath");
			String keystoreProvider = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName,
					"keystoreProvider");
			String keystoreRelativeTo = (String) mbeanServerConnection.getAttribute(serverIdentityMBeanName,
					"keystoreRelativeTo");

			String mBeanPath = "jboss.as:path=" + keystoreRelativeTo;
			ObjectName pathMBean = new ObjectName(mBeanPath);
			String absolutePath = (String) mbeanServerConnection.getAttribute(pathMBean, "path");

			log.fine(String.format(
					"Alias: %s KeyPassword: %s KeystorePassword: %s KeystorePath: %s KeystoreProvider: %s KeystoreRelativeTo: %s AbsolutePath: %s",
					alias, keyPassword, keystorePassword, keystorePath, keystoreProvider, keystoreRelativeTo,
					absolutePath));

			KeyStore ks = KeyStore.getInstance(keystoreProvider);

			FileInputStream fis = getKeyStoreFileStream(Paths.get(absolutePath, keystorePath).toString());

			ks.load(fis, keystorePassword.toCharArray());
			Certificate certificateFromStore = ks.getCertificate(alias);
			if (certificateFromStore instanceof X509Certificate) {
				certificate = (X509Certificate) certificateFromStore;
			} else {
				log.warning(String.format("Certificate is not a X509Certitificate it is: %s",
						certificateFromStore != null ? certificateFromStore.getClass().getName() : null));
			}
			Key keyFromStore = ks.getKey(alias, keyPassword.toCharArray());

			if (keyFromStore instanceof PrivateKey) {
				privateKey = (PrivateKey) keyFromStore;
			} else {
				log.warning(String.format("Key is not a PrivateKey it is: %s",
						keyFromStore != null ? keyFromStore.getClass().getName() : null));
			}
			fis.close();

		} catch (MalformedObjectNameException | InstanceNotFoundException | AttributeNotFoundException
				| ReflectionException | MBeanException | IOException | KeyStoreException | NoSuchAlgorithmException
				| CertificateException | UnrecoverableKeyException e) {
			log.log(Level.WARNING, "Could not get SSL Certificate and Keys", e);
		}
	}

	private FileInputStream getKeyStoreFileStream(String filePath) throws IOException {
		return new FileInputStream(filePath);
	}

	/**
	 * Returns the public key in the JSON Web Key Format (JWK)
	 * 
	 * https://tools.ietf.org/html/rfc7517
	 * 
	 * @return
	 */
	@GET
	@Path("/jwk")
	public String jwk() {

		PublicKey publicKey = certificate.getPublicKey();
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new IllegalArgumentException("The given key is not a RSA  key. It is: "
					+ (publicKey != null ? publicKey.getClass().getName() : ""));
		}

		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

		return Json.createObjectBuilder().add("kty", "RSA")
				.add("n", Base64.getEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray()))
				.add("e", Base64.getEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray())).build()
				.toString();
	}

	@GET
	@Path("/jwt")
	public Response jwt(@Context HttpServletRequest httpServletRequest) {

		String authorization = httpServletRequest.getHeader("Authorization");
		// btoa("admin:admin") "YWRtaW46YWRtaW4="
		if (authorization != null && authorization.equals("Basic YWRtaW46YWRtaW4=")) {

			PublicKey publicKey = certificate.getPublicKey();
			if (!(publicKey instanceof RSAPublicKey)) {
				throw new IllegalArgumentException("The given key is not a RSA  key. It is: "
						+ (publicKey != null ? publicKey.getClass().getName() : ""));
			}

			RsaJsonWebKey rsaJsonWebKey = new RsaJsonWebKey((RSAPublicKey) publicKey);
			rsaJsonWebKey.setPrivateKey(privateKey);
			// Create the Claims, which will be the content of the JWT
			JwtClaims claims = new JwtClaims();

			Principal principal = certificate.getSubjectDN();
			claims.setIssuer("https://" + principal.getName().replaceAll("CN=", "").replaceAll(",.*", "")); // who
																											// creates
			// the token and
			// signs it
			claims.setAudience("*.incentergy.de"); // to whom the token is intended
													// to be sent
			claims.setExpirationTimeMinutesInTheFuture(30 * 24 * 60); // time when
																		// the token
																		// will
																		// expire
																		// (10
																		// minutes
																		// from now)
			claims.setGeneratedJwtId(); // a unique identifier for the token
			claims.setIssuedAtToNow(); // when the token was issued/created (now)
			claims.setNotBeforeMinutesInThePast(2); // time before which the token
													// is not yet valid (2 minutes
													// ago)
			claims.setSubject("admin"); // the subject/principal is whom the
			// token is about

			claims.setClaim("email", "admin@example.com"); // additional
															// claims/attributes
															// about the subject can
															// be added
			claims.setClaim("loginName", "admin"); // additional
													// claims/attributes
													// about the
													// subject can
													// be added
			claims.setStringListClaim("groups", Arrays.asList("Administrator", "Manager", "Employee")); // multi-valued
			// claims
			// work too
			// and will
			// end up as
			// a JSON
			// array

			// A JWT is a JWS and/or a JWE with JSON claims as the payload.
			// In this example it is a JWS so we create a JsonWebSignature object.
			JsonWebSignature jws = new JsonWebSignature();

			// The payload of the JWS is JSON content of the JWT Claims
			jws.setPayload(claims.toJson());

			// The JWT is signed using the private key
			jws.setKey(rsaJsonWebKey.getPrivateKey());

			// Set the Key ID (kid) header because it's just the polite thing to do.
			// We only have one key in this example but a using a Key ID helps
			// facilitate a smooth key rollover process
			if (rsaJsonWebKey.getKeyId() != null) {
				jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
			}

			// Set the signature algorithm on the JWT/JWS that will integrity
			// protect the claims
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

			// Sign the JWS and produce the compact serialization or the complete
			// JWT/JWS
			// representation, which is a string consisting of three dot ('.')
			// separated
			// base64url-encoded parts in the form Header.Payload.Signature
			// If you wanted to encrypt it, you can simply set this jwt as the
			// payload
			// of a JsonWebEncryption object and set the cty (Content Type) header
			// to "jwt".
			String jwt = "";
			try {
				jwt = jws.getCompactSerialization();
			} catch (JoseException e) {
				log.log(Level.SEVERE, "Could not generate JWT Token", e);
			}

			// Now you can do something with the JWT. Like send it to some other
			// party
			// over the clouds and through the interwebs.
			log.fine("JWT: " + jwt);
			return Response.ok(jwt, "text/plain").build();
		} else {
			return Response.status(Response.Status.UNAUTHORIZED).build();
		}
	}
}