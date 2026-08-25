/*
 * Copyright 2023 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.spnego;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOLoginService;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.ConnectionMetaData;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import javax.security.auth.Subject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.partialMockBuilder;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.powermock.api.support.Stubber.stubMethod;

/**
 * Unit tests for {@link SpnegoLoginServiceWithAuthServiceLifecycle}
 */
@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.management.*", "org.ietf.jgss.GSSManager"})
@PrepareForTest(SpnegoLoginServiceWithAuthServiceLifecycle.class)
public class SpnegoLoginServiceWithAuthServiceLifecycleTest {
    public static final String USERNAME = "user1";
    private static final String REALM = "TEST_REALM";
    private static final String TOKEN = "TEST_TOKEN";
    private static final String ROLE = "ADMIN";
    private static final Subject SUBJECT = new Subject();
    private static final List<String> ATL_RULES = Collections.singletonList("RULE:[1:$1@$0](.*@.*)s/@.*/foo/");
    private static final Function<Boolean, Session> SESSION_FN = create -> mock(Session.class);
    private final CruiseControlAuthorizationService _mockAuthorizationService = mock(CruiseControlAuthorizationService.class);
    private final SPNEGOLoginService _mockLoginService = mock(SPNEGOLoginService.class);
    private final Request _mockRequest = mock(Request.class);
    private final UserIdentity _mockAuthIdentity = mock(UserIdentity.class);
    private final UserIdentity _mockRoleIdentity = mock(UserIdentity.class);
    private final GSSContext _mockGSSContext = mock(GSSContext.class);

    /**
     * Init the unit test.
     */
    @Before
    public void setup() throws GSSException {
        expect(_mockLoginService.login(anyString(), anyObject(), anyObject(), anyObject())).andReturn(_mockAuthIdentity);
        expect(_mockAuthIdentity.getSubject()).andReturn(SUBJECT);
        expect(_mockRoleIdentity.isUserInRole(ROLE)).andReturn(true);
        ConnectionMetaData connectionMetaData = mock(ConnectionMetaData.class);
        expect(connectionMetaData.getRemoteSocketAddress()).andReturn(new InetSocketAddress("127.0.0.1", 0)).anyTimes();
        expect(_mockRequest.getConnectionMetaData()).andReturn(connectionMetaData).anyTimes();
        replay(connectionMetaData);
    }

    @Test
    public void testExtractSpnegoContext() throws ReflectiveOperationException {
        SpnegoLoginServiceWithAuthServiceLifecycle service = partialMockBuilder(SpnegoLoginServiceWithAuthServiceLifecycle.class).createMock();
        Whitebox.setInternalState(service, "_spnegoLoginService", _mockLoginService);
        Class<?> contextClass = Class.forName("org.eclipse.jetty.security.SPNEGOLoginService$SPNEGOContext");
        Constructor<?> contextCtor = contextClass.getDeclaredConstructor();
        contextCtor.setAccessible(true);
        Object context = contextCtor.newInstance();
        Field contextField = SPNEGOLoginService.class.getDeclaredField("_context");
        contextField.setAccessible(true);
        contextField.set(_mockLoginService, context);
        replay(service);

        service.extractSpnegoContext();
    }

    @Test
    public void testLoginWithoutKerberosRules() {
        SpnegoLoginServiceWithAuthServiceLifecycle service = createAuthServiceWithMocking(new SPNEGOUserPrincipal(USERNAME, TOKEN));
        replay(service, _mockLoginService, _mockAuthorizationService, _mockAuthIdentity, _mockRoleIdentity, _mockRequest);

        UserIdentity userIdentity = service.login(USERNAME, new Object(), _mockRequest, SESSION_FN);

        assertUserIdentity(USERNAME, userIdentity);
    }

    @Test
    public void testLoginWithKerberosRules() {
        String principalName = "user1@realm";
        String usernameReplaced = USERNAME + "foo";
        SPNEGOUserPrincipal principal = new SPNEGOUserPrincipal(principalName, TOKEN);
        SpnegoLoginServiceWithAuthServiceLifecycle service = createAuthServiceWithMocking(principalName, usernameReplaced, principal);
        Whitebox.setInternalState(service, "_kerberosShortNamer", KerberosShortNamer.fromUnparsedRules(REALM, ATL_RULES));
        replay(service, _mockLoginService, _mockAuthorizationService, _mockAuthIdentity, _mockRoleIdentity, _mockRequest);

        UserIdentity userIdentity = service.login(principalName, new Object(), _mockRequest, SESSION_FN);

        assertUserIdentity(usernameReplaced, userIdentity);
    }

    private SpnegoLoginServiceWithAuthServiceLifecycle createAuthServiceWithMocking(SPNEGOUserPrincipal principal) {
        return createAuthServiceWithMocking(USERNAME, USERNAME, principal);
    }

    private SpnegoLoginServiceWithAuthServiceLifecycle createAuthServiceWithMocking(String name, String finalName, SPNEGOUserPrincipal principal) {
        SpnegoLoginServiceWithAuthServiceLifecycle service = partialMockBuilder(SpnegoLoginServiceWithAuthServiceLifecycle.class).createMock();
        stubMethod(SpnegoLoginServiceWithAuthServiceLifecycle.class, "getFullPrincipalFromGssContext", name);
        stubMethod(SpnegoLoginServiceWithAuthServiceLifecycle.class, "addContext", _mockGSSContext);

        Whitebox.setInternalState(service, "_authorizationService", _mockAuthorizationService);
        Whitebox.setInternalState(service, "_spnegoLoginService", _mockLoginService);

        expect(_mockAuthIdentity.getUserPrincipal()).andReturn(principal);
        expect(_mockAuthorizationService.getUserIdentity(anyString(), anyString())).andReturn(_mockRoleIdentity);

        return service;
    }

    private void assertUserIdentity(String username, UserIdentity userIdentity) {
        assertEquals(username, userIdentity.getUserPrincipal().getName());
        assertEquals(SUBJECT, userIdentity.getSubject());
        assertTrue(userIdentity instanceof RoleDelegateUserIdentity);
        assertTrue(userIdentity.isUserInRole(ROLE));
        verify(_mockLoginService, _mockAuthorizationService, _mockRoleIdentity);
    }

}
