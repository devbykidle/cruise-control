/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.jwt;

import com.linkedin.kafka.cruisecontrol.servlet.security.SecurityUtils;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreAuthorizationService;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.ConnectionMetaData;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.junit.Test;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.function.Function;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class JwtLoginServiceTest {

  private static final String TEST_USER = "testUser";
  private static final Function<Boolean, Session> NO_SESSION = create -> null;

  @Test
  public void testValidateTokenSuccessfully() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(tokenAndKeys.token());

    replay(request);
    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    verify(request);
    assertNotNull(identity);
    assertEquals(TEST_USER, identity.getUserPrincipal().getName());
  }

  @Test
  public void testFailSignatureValidation() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER);
    // This will be signed with a different key
    TokenGenerator.TokenAndKeys tokenAndKeys2 = TokenGenerator.generateToken(TEST_USER);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys2.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(null);

    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    assertNull(identity);
  }

  @Test
  public void testFailAudienceValidation() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER, Arrays.asList("A", "B"));
    JwtLoginService loginService = new JwtLoginService(
        new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), Arrays.asList("C", "D"));

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(null);

    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    assertNull(identity);
  }

  @Test
  public void testFailExpirationValidation() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER, 1L);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(null);

    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    assertNull(identity);
  }

  @Test
  public void testRevalidateTokenPasses() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(tokenAndKeys.token());

    replay(request);
    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    verify(request);
    assertNotNull(identity);
    assertEquals(TEST_USER, identity.getUserPrincipal().getName());
    assertTrue(loginService.validate(identity));
  }

  @Test
  public void testRevalidateTokenFails() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    Instant now = Instant.now();
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER, now.plusSeconds(10).toEpochMilli());
    Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);
    JwtLoginService loginService = new JwtLoginService(
        new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null, fixedClock);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(tokenAndKeys.token());

    replay(request);
    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    verify(request);
    assertNotNull(identity);
    assertEquals(TEST_USER, identity.getUserPrincipal().getName());
    loginService.setClock(Clock.offset(fixedClock, Duration.ofSeconds(20)));
    assertFalse(loginService.validate(identity));
  }

  @Test
  public void testFailMissingRole() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser("otherUser", SecurityUtils.NO_CREDENTIAL, new String[] {"USER"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(tokenAndKeys.token());

    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    assertNull(identity);
  }

  @Test
  public void testMultipleRoles() throws Exception {
    UserStore testUserStore = new UserStore();
    testUserStore.addUser(TEST_USER, SecurityUtils.NO_CREDENTIAL, new String[] {"USER", "ADMIN"});
    TokenGenerator.TokenAndKeys tokenAndKeys = TokenGenerator.generateToken(TEST_USER);
    JwtLoginService loginService = new JwtLoginService(new UserStoreAuthorizationService(testUserStore), tokenAndKeys.publicKey(), null);

    SignedJWT jwtToken = SignedJWT.parse(tokenAndKeys.token());
    Request request = mockRequestWithTokenAttribute(tokenAndKeys.token());
    replay(request);
    UserIdentity identity = loginService.login(TEST_USER, jwtToken, request, NO_SESSION);
    verify(request);
    assertNotNull(identity);
    assertTrue(identity.isUserInRole("USER"));
    assertTrue(identity.isUserInRole("ADMIN"));
  }

  private static Request mockRequestWithTokenAttribute(String token) {
    Request request = mock(Request.class);
    ConnectionMetaData connectionMetaData = mock(ConnectionMetaData.class);
    expect(connectionMetaData.getRemoteSocketAddress()).andReturn(new InetSocketAddress("127.0.0.1", 0)).anyTimes();
    expect(request.getConnectionMetaData()).andReturn(connectionMetaData).anyTimes();
    if (token != null) {
      expect(request.getAttribute(JwtAuthenticator.JWT_TOKEN_REQUEST_ATTRIBUTE)).andReturn(token).anyTimes();
    }
    replay(connectionMetaData);
    return request;
  }
}
