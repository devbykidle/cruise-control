/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.trustedproxy;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.DefaultRoleSecurityProvider;
import com.linkedin.kafka.cruisecontrol.servlet.security.SecurityUtils;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreIdentities;
import com.linkedin.kafka.cruisecontrol.servlet.security.spnego.SpnegoLoginServiceWithAuthServiceLifecycle;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.ConnectionMetaData;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.junit.Test;
import javax.security.auth.Subject;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.function.Function;

import static com.linkedin.kafka.cruisecontrol.servlet.parameters.ParameterUtils.DO_AS;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TrustedProxyLoginServiceTest {

  public static final String TEST_SERVICE_USER = "testServiceUser";
  public static final String ENCODED_TOKEN = "encoded_token";
  public static final String TEST_USER = "testUser";
  private static final Function<Boolean, Session> NO_SESSION = create -> null;

  private static class TestAuthorizer implements CruiseControlAuthorizationService {

    private final UserStore _adminUserStore = new UserStore();

    TestAuthorizer(String testUser) {
      _adminUserStore.addUser(testUser, SecurityUtils.NO_CREDENTIAL, new String[] { DefaultRoleSecurityProvider.ADMIN });
    }

    @Override
    public UserIdentity getUserIdentity(String remoteAddr, String name) {
      return UserStoreIdentities.getUserIdentity(_adminUserStore, name);
    }
  }

  private final SpnegoLoginServiceWithAuthServiceLifecycle _mockSpnegoLoginService = mock(SpnegoLoginServiceWithAuthServiceLifecycle.class);
  private final SpnegoLoginServiceWithAuthServiceLifecycle _mockFallbackLoginService = mock(SpnegoLoginServiceWithAuthServiceLifecycle.class);

  @Test
  public void testSuccessfulAuthentication() {
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(TEST_SERVICE_USER, ENCODED_TOKEN);
    UserIdentity serviceDelegate = mock(UserIdentity.class);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, serviceDelegate);
    expect(_mockSpnegoLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(TEST_USER);
    Request mockRequest = mockRequestWithDoAs(TEST_USER);

    replay(_mockSpnegoLoginService, mockRequest);

    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, false);
    UserIdentity doAsIdentity = trustedProxyLoginService.login(null, ENCODED_TOKEN, mockRequest, NO_SESSION);
    assertNotNull(doAsIdentity);
    assertNotNull(doAsIdentity.getUserPrincipal());
    assertEquals(TEST_USER, doAsIdentity.getUserPrincipal().getName());
    assertEquals(((TrustedProxyPrincipal) doAsIdentity.getUserPrincipal()).servicePrincipal(), servicePrincipal);
    assertTrue(((RoleDelegateUserIdentity) doAsIdentity).isEstablished());
    verify(_mockSpnegoLoginService, mockRequest);
  }

  @Test
  public void testNoDoAsUser() {
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(TEST_SERVICE_USER, ENCODED_TOKEN);
    UserIdentity serviceDelegate = mock(UserIdentity.class);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, serviceDelegate);
    expect(_mockSpnegoLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(TEST_USER);
    Request mockRequest = mockRequestWithDoAs(null);

    replay(_mockSpnegoLoginService, mockRequest);

    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, false);
    UserIdentity doAsIdentity = trustedProxyLoginService.login(null, ENCODED_TOKEN, mockRequest, NO_SESSION);
    assertNotNull(doAsIdentity);
    assertNotNull(doAsIdentity.getUserPrincipal());
    assertNull(doAsIdentity.getUserPrincipal().getName());
    assertFalse(((RoleDelegateUserIdentity) doAsIdentity).isEstablished());
    verify(_mockSpnegoLoginService, mockRequest);
  }

  @Test
  public void testInvalidAuthServiceUser() {
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(TEST_SERVICE_USER, ENCODED_TOKEN);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, null);
    expect(_mockSpnegoLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(TEST_USER);
    Request mockRequest = mockRequestWithDoAs(TEST_USER);
    replay(_mockSpnegoLoginService, mockRequest);

    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, false);
    UserIdentity doAsIdentity = trustedProxyLoginService.login(null, ENCODED_TOKEN, mockRequest, NO_SESSION);
    assertNotNull(doAsIdentity);
    assertFalse(((RoleDelegateUserIdentity) doAsIdentity).isEstablished());
  }

  @Test
  public void testFallbackToSpnego() {
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(TEST_SERVICE_USER, ENCODED_TOKEN);
    UserIdentity serviceDelegate = mock(UserIdentity.class);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, serviceDelegate);
    expect(_mockFallbackLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(TEST_USER);
    Request mockRequest = mockRequestWithDoAs(null);
    replay(_mockFallbackLoginService, mockRequest);

    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, true);
    UserIdentity doAsIdentity = trustedProxyLoginService.login(null, ENCODED_TOKEN, mockRequest, NO_SESSION);
    assertNotNull(doAsIdentity);
    assertNotNull(doAsIdentity.getUserPrincipal());
    assertEquals(servicePrincipal, doAsIdentity.getUserPrincipal());
    verify(_mockFallbackLoginService, mockRequest);
  }

  @Test
  public void testTrustedProxyWithKerberosRules() {
    String username = "user1";
    String proxy = "proxy2@realm";
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(proxy, ENCODED_TOKEN);
    UserIdentity serviceDelegate = mock(UserIdentity.class);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, serviceDelegate);
    expect(_mockSpnegoLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(username);
    Request mockRequest = mockRequestWithDoAs(username);
    replay(_mockSpnegoLoginService, mockRequest);
    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, false);

    UserIdentity doAsIdentity = trustedProxyLoginService.login(proxy, ENCODED_TOKEN, mockRequest, NO_SESSION);

    assertNotNull(doAsIdentity);
    assertNotNull(doAsIdentity.getUserPrincipal());
    assertEquals(username, doAsIdentity.getUserPrincipal().getName());
    assertEquals(((TrustedProxyPrincipal) doAsIdentity.getUserPrincipal()).servicePrincipal(), servicePrincipal);
    verify(_mockSpnegoLoginService, mockRequest);
  }

  @Test
  public void testFallbackToSpnegoWithKerberosRules() {
    String username = "user1";
    String principal = "user1@realm";
    String usernameReplaced = username + "foo";
    SPNEGOUserPrincipal servicePrincipal = new SPNEGOUserPrincipal(usernameReplaced, ENCODED_TOKEN);
    UserIdentity serviceDelegate = mock(UserIdentity.class);
    Subject subject = new Subject(true, Collections.singleton(servicePrincipal), Collections.emptySet(), Collections.emptySet());
    RoleDelegateUserIdentity result = new RoleDelegateUserIdentity(subject, servicePrincipal, serviceDelegate);
    expect(_mockFallbackLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(result);

    TestAuthorizer userAuthorizer = new TestAuthorizer(username);
    Request mockRequest = mockRequestWithDoAs(null);
    replay(_mockFallbackLoginService, mockRequest);
    TrustedProxyLoginService trustedProxyLoginService = new TrustedProxyLoginService(_mockSpnegoLoginService, _mockFallbackLoginService,
            userAuthorizer, true);

    UserIdentity doAsIdentity = trustedProxyLoginService.login(principal, ENCODED_TOKEN, mockRequest, NO_SESSION);

    assertNotNull(doAsIdentity);
    assertNotNull(doAsIdentity.getUserPrincipal());
    SPNEGOUserPrincipal doAsPrincipal = (SPNEGOUserPrincipal) doAsIdentity.getUserPrincipal();
    assertEquals(servicePrincipal.getName(), doAsPrincipal.getName());
    assertTrue(((RoleDelegateUserIdentity) doAsIdentity).isEstablished());
    verify(_mockFallbackLoginService, mockRequest);
  }

  private static Request mockRequestWithDoAs(String doAsUser) {
    Request request = mock(Request.class);
    HttpURI uri = doAsUser == null
        ? HttpURI.build("/state")
        : HttpURI.build("/state?" + DO_AS + "=" + doAsUser);
    expect(request.getHttpURI()).andReturn(uri).anyTimes();
    ConnectionMetaData connectionMetaData = mock(ConnectionMetaData.class);
    expect(connectionMetaData.getRemoteSocketAddress()).andReturn(new InetSocketAddress("127.0.0.1", 0)).anyTimes();
    expect(request.getConnectionMetaData()).andReturn(connectionMetaData).anyTimes();
    replay(connectionMetaData);
    return request;
  }
}
