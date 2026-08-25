/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.jwt;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreAuthorizationService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.component.LifeCycle;

import static com.linkedin.kafka.cruisecontrol.servlet.security.jwt.JwtAuthenticator.JWT_LOGGER;

/**
 * <p>This class validates a JWT token. The token must be cryptographically encrypted and it uses an RSA public key for
 * validation that is expected to be stored in a PEM formatted file.</p>
 * <p>This class implements {@link AbstractLifeCycle} which means it is a managed bean, its lifecycle will be managed
 * by Jetty. It's {@link CruiseControlAuthorizationService} can also be an {@link AbstractLifeCycle} in which case it
 * delegates to this class, so opening and closing connections should be done by implementing the
 * {@link AbstractLifeCycle} interface's {@link #doStart()} and {@link #doStop()} methods respectively. For a simple
 * example see {@link UserStoreAuthorizationService}.</p>
 * <p>The login service also validates expiration time of the token and it expects the token to contain the expiration
 * in Unix epoch time format in UTC.</p>
 */
public class JwtLoginService extends AbstractLifeCycle implements LoginService {

  public static final String X_509_CERT_TYPE = "X.509";
  private final CruiseControlAuthorizationService _authorizationService;
  private IdentityService _identityService;
  private final RSAPublicKey _publicKey;
  private final List<String> _audiences;
  private Clock _clock;

  public JwtLoginService(CruiseControlAuthorizationService authorizationService, String publicKeyLocation, List<String> audiences)
      throws IOException, CertificateException {
    this(authorizationService, readPublicKey(publicKeyLocation), audiences);
  }

  public JwtLoginService(CruiseControlAuthorizationService authorizationService, RSAPublicKey publicKey, List<String> audiences) {
    this(authorizationService, publicKey, audiences, Clock.systemUTC());
  }

  public JwtLoginService(CruiseControlAuthorizationService authorizationService, RSAPublicKey publicKey, List<String> audiences, Clock clock) {
    _authorizationService = authorizationService;
    _identityService = new DefaultIdentityService();
    _publicKey = publicKey;
    _audiences = audiences;
    _clock = clock;
  }

  @Override
  protected void doStart() throws Exception {
    super.doStart();
    if (_authorizationService instanceof LifeCycle) {
      ((LifeCycle) _authorizationService).start();
    }
  }

  @Override
  protected void doStop() throws Exception {
    if (_authorizationService instanceof LifeCycle) {
      ((LifeCycle) _authorizationService).stop();
    }
    super.doStop();
  }

  @Override
  public String getName() {
    return null;
  }

  @Override
  public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getSession) {
    if (!(credentials instanceof SignedJWT)) {
      return null;
    }
    if (request == null) {
      return null;
    }

    SignedJWT jwtToken = (SignedJWT) credentials;
    JWTClaimsSet claimsSet;
    boolean valid;
    try {
      claimsSet = jwtToken.getJWTClaimsSet();
      valid = validateToken(jwtToken, claimsSet, username);
    } catch (ParseException e) {
      JWT_LOGGER.warn(String.format("%s: Couldn't parse a JWT token", username), e);
      return null;
    }
    if (valid) {
      // Prefer the original serialized token from the servlet request attribute when present;
      // fall back to re-serializing the already-parsed JWT (Jetty 12 LoginService receives a core Request).
      Object attributeToken = request.getAttribute(JwtAuthenticator.JWT_TOKEN_REQUEST_ATTRIBUTE);
      String serializedToken = attributeToken instanceof String ? (String) attributeToken : jwtToken.serialize();
      UserIdentity rolesDelegate = _authorizationService.getUserIdentity(remoteAddr(request), username);
      if (rolesDelegate == null) {
        return null;
      } else {
        return getUserIdentity(jwtToken, claimsSet, serializedToken, username, rolesDelegate);
      }
    } else {
      return null;
    }
  }

  @Override
  public boolean validate(UserIdentity user) {
    Set<JWTClaimsSet> claims = user.getSubject().getPrivateCredentials(JWTClaimsSet.class);
    return !claims.isEmpty() && claims.stream().allMatch(this::validateExpiration);
  }

  @Override
  public IdentityService getIdentityService() {
    return _identityService;
  }

  @Override
  public void setIdentityService(IdentityService service) {
    _identityService = service;
  }

  @Override
  public void logout(UserIdentity user) {

  }

  // visible for testing
  void setClock(Clock newClock) {
    _clock = newClock;
  }

  private boolean validateToken(SignedJWT jwtToken, JWTClaimsSet claimsSet, String username) {
    boolean sigValid = validateSignature(jwtToken);
    if (!sigValid) {
      JWT_LOGGER.warn(String.format("%s: Signature could not be verified", username));
    }
    boolean audValid = validateAudiences(claimsSet);
    if (!audValid) {
      JWT_LOGGER.warn(String.format("%s: Audience validation failed", username));
    }
    boolean expValid = validateExpiration(claimsSet);
    if (!expValid) {
      JWT_LOGGER.warn(String.format("%s: Expiration validation failed", username));
    }

    return sigValid && audValid && expValid;
  }

  private boolean validateSignature(SignedJWT jwtToken) {
    if (JWSObject.State.SIGNED != jwtToken.getState() || jwtToken.getSignature() == null) {
      return false;
    }
    JWSVerifier verifier = new RSASSAVerifier(_publicKey);
    try {
      return jwtToken.verify(verifier);
    } catch (JOSEException e) {
      JWT_LOGGER.warn("Couldn't verify the signature of a token", e);
      return false;
    }
  }

  private boolean validateAudiences(JWTClaimsSet claimsSet) {
    if (_audiences == null) {
      return true;
    }
    List<String> tokenAudienceList = claimsSet.getAudience();
    for (String aud : tokenAudienceList) {
      if (_audiences.contains(aud)) {
        JWT_LOGGER.trace("JWT token audience has been successfully validated");
        return true;
      }
    }
    JWT_LOGGER.trace("Couldn't find a valid audience");
    return false;
  }

  private boolean validateExpiration(JWTClaimsSet claimsSet) {
    Date expires = claimsSet.getExpirationTime();
    return expires == null || _clock.instant().isBefore(expires.toInstant());
  }

  private static RSAPublicKey readPublicKey(String location) throws CertificateException, IOException {
    byte[] publicKeyBytes = Files.readAllBytes(Paths.get(location));
    CertificateFactory fact = CertificateFactory.getInstance(X_509_CERT_TYPE);
    X509Certificate cer = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(publicKeyBytes));
    return (RSAPublicKey) cer.getPublicKey();
  }

  private static UserIdentity getUserIdentity(SignedJWT jwtToken, JWTClaimsSet claimsSet, String serializedToken,
                                              String username, UserIdentity rolesDelegate) {
    JwtUserPrincipal principal = new JwtUserPrincipal(username, serializedToken);
    Set<Object> privCreds = new HashSet<>();
    privCreds.add(jwtToken);
    privCreds.add(claimsSet);
    Subject subject = new Subject(true, Collections.singleton(principal), Collections.emptySet(), privCreds);
    return new JwtUserIdentity(subject, principal, rolesDelegate);
  }

  private static String remoteAddr(Request request) {
    SocketAddress address = request.getConnectionMetaData().getRemoteSocketAddress();
    if (address instanceof InetSocketAddress) {
      InetSocketAddress inet = (InetSocketAddress) address;
      if (inet.getAddress() != null) {
        return inet.getAddress().getHostAddress();
      }
      return inet.getHostString();
    }
    return address == null ? null : address.toString();
  }
}
