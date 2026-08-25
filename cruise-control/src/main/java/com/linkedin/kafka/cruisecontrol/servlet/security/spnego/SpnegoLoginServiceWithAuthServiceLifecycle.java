/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.spnego;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.DummyRoleLoginService;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreAuthorizationService;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Function;
import javax.security.auth.Subject;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOLoginService;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps Jetty 12 {@link SPNEGOLoginService} to manage {@link CruiseControlAuthorizationService} lifecycle
 * and apply Kerberos auth-to-local rules using the full GSS principal (including realm).
 *
 * @see UserStoreAuthorizationService
 */
public class SpnegoLoginServiceWithAuthServiceLifecycle extends ContainerLifeCycle implements LoginService {

  private static final Logger LOG = LoggerFactory.getLogger(SpnegoLoginServiceWithAuthServiceLifecycle.class);
  private static final String GSS_HOLDER_CLASS_NAME = "org.eclipse.jetty.security.SPNEGOLoginService$GSSContextHolder";
  private final GSSManager _gssManager = GSSManager.getInstance();
  private final SPNEGOLoginService _spnegoLoginService;
  private final CruiseControlAuthorizationService _authorizationService;
  private final KerberosShortNamer _kerberosShortNamer;
  private Subject _spnegoSubject;
  private GSSCredential _spnegoServiceCredential;
  private Constructor<?> _holderConstructor;
  private String _gssHolderAttribute;

  public SpnegoLoginServiceWithAuthServiceLifecycle(String realm, CruiseControlAuthorizationService authorizationService,
                                                    List<String> principalToLocalRules) {
    _spnegoLoginService = new SPNEGOLoginService(realm, new DummyRoleLoginService());
    _authorizationService = authorizationService;
    _kerberosShortNamer = principalToLocalRules == null || principalToLocalRules.isEmpty()
            ? null
            : KerberosShortNamer.fromUnparsedRules(realm, principalToLocalRules);
  }

  @Override
  protected void doStart() throws Exception {
    addBean(_spnegoLoginService);
    if (_authorizationService instanceof org.eclipse.jetty.util.component.LifeCycle) {
      addBean(_authorizationService);
    }
    super.doStart();
    extractSpnegoContext();
  }

  @Override
  public String getName() {
    return _spnegoLoginService.getName();
  }

  @Override
  public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getSession) {
    Session session = getSession.apply(Boolean.TRUE);
    GSSContext gssContext = addContext(session);

    UserIdentity userIdentity = _spnegoLoginService.login(username, credentials, request, getSession);
    if (userIdentity == null || !(userIdentity.getUserPrincipal() instanceof SPNEGOUserPrincipal)) {
      return userIdentity;
    }
    SPNEGOUserPrincipal userPrincipal = (SPNEGOUserPrincipal) userIdentity.getUserPrincipal();

    String fullPrincipal = getFullPrincipalFromGssContext(gssContext);
    LOG.debug("User {} logged in with full principal {}", userPrincipal.getName(), fullPrincipal);
    String userShortname = getSpnegoUserPrincipalShortname(fullPrincipal);

    userPrincipal = new SPNEGOUserPrincipal(userShortname, userPrincipal.getEncodedToken());
    UserIdentity roleDelegate = _authorizationService.getUserIdentity(remoteAddr(request), userShortname);
    return new RoleDelegateUserIdentity(userIdentity.getSubject(), userPrincipal, roleDelegate);
  }

  @Override
  public boolean validate(UserIdentity user) {
    return _spnegoLoginService.validate(user);
  }

  @Override
  public IdentityService getIdentityService() {
    return _spnegoLoginService.getIdentityService();
  }

  @Override
  public void setIdentityService(IdentityService service) {
    _spnegoLoginService.setIdentityService(service);
  }

  @Override
  public void logout(UserIdentity user) {
    _spnegoLoginService.logout(user);
  }

  public void setServiceName(String serviceName) {
    _spnegoLoginService.setServiceName(serviceName);
  }

  public void setHostName(String hostName) {
    _spnegoLoginService.setHostName(hostName);
  }

  public void setKeyTabPath(Path keyTabFile) {
    _spnegoLoginService.setKeyTabPath(keyTabFile);
  }

  private String getSpnegoUserPrincipalShortname(String fullPrincipal) {
    PrincipalName userPrincipalName = PrincipalValidator.parsePrincipal("", fullPrincipal);

    if (_kerberosShortNamer == null) {
      return userPrincipalName.getPrimary();
    }

    try {
      String userShortname = _kerberosShortNamer.shortName(new KerberosName(userPrincipalName.getPrimary(),
              userPrincipalName.getInstance(), userPrincipalName.getRealm()));
      LOG.debug("Principal {} was shortened to {}", userPrincipalName, userShortname);
      return userShortname;
    } catch (IOException e) {
      throw new RuntimeException("Could not generate short name for principal " + userPrincipalName, e);
    }
  }

  private String getFullPrincipalFromGssContext(GSSContext gssContext) {
    try {
      return gssContext.getSrcName().toString();
    } catch (GSSException e) {
      throw new RuntimeException("Failed to extract full principal", e);
    }
  }

  // Visible for testing
  void extractSpnegoContext() {
    // Depends on SPNEGOLoginService internal structure (SPNEGOContext / GSSContextHolder).
    // If Jetty is upgraded, this code might break.
    try {
      Field contextField = SPNEGOLoginService.class.getDeclaredField("_context");
      contextField.setAccessible(true);
      Object spnegoContext = contextField.get(_spnegoLoginService);
      Class<?> contextClass = spnegoContext.getClass();
      Field contextSubjectField = contextClass.getDeclaredField("_subject");
      contextSubjectField.setAccessible(true);
      _spnegoSubject = (Subject) contextSubjectField.get(spnegoContext);
      Field contextCredentialField = contextClass.getDeclaredField("_serviceCredential");
      contextCredentialField.setAccessible(true);
      _spnegoServiceCredential = (GSSCredential) contextCredentialField.get(spnegoContext);
      Class<?> gssHolder = Class.forName(GSS_HOLDER_CLASS_NAME);
      Field attributeField = gssHolder.getField("ATTRIBUTE");
      _gssHolderAttribute = (String) attributeField.get(null);
      _holderConstructor = gssHolder.getDeclaredConstructor(GSSContext.class);
      _holderConstructor.setAccessible(true);
    } catch (NoSuchFieldException | IllegalAccessException | ClassNotFoundException | NoSuchMethodException e) {
      throw new RuntimeException("Failed to init SPNEGO context", e);
    }
  }

  private GSSContext addContext(Session session) {
    // Inject an externally created GSSContext so we can read the full Kerberos principal (with realm)
    // for auth-to-local rules. SPNEGOLoginService otherwise drops the realm from the client principal.
    try {
      GSSContext gssContext = callAs(_spnegoSubject, newGSSContext(_spnegoServiceCredential));
      Object holder = _holderConstructor.newInstance(gssContext);
      session.setAttribute(_gssHolderAttribute, holder);
      return gssContext;
    } catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
      throw new RuntimeException("Failed to perform SPNEGO authentication", e);
    }
  }

  private static <T> T callAs(Subject subject, Callable<T> action) {
    return org.eclipse.jetty.util.security.SecurityUtils.doAs(subject, action);
  }

  private Callable<GSSContext> newGSSContext(GSSCredential serviceCredential) {
    return () -> {
      try {
        return _gssManager.createContext(serviceCredential);
      } catch (GSSException e) {
        throw new RuntimeException(e);
      }
    };
  }

  private static String remoteAddr(Request request) {
    if (request == null) {
      return null;
    }
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
