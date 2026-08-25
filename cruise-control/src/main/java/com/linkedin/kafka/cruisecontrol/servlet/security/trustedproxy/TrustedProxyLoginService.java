/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.trustedproxy;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.spnego.SpnegoLoginServiceWithAuthServiceLifecycle;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.component.ContainerLifeCycle;
import org.eclipse.jetty.util.component.LifeCycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.linkedin.kafka.cruisecontrol.servlet.parameters.ParameterUtils.DO_AS;

/**
 * {@code TrustedProxyLoginService} is a special SPNEGO login service where we only allow a list of trusted services
 * to act on behalf of clients. The login service authenticates the trusted party but creates credentials for the client
 * based on the {@link CruiseControlAuthorizationService}.
 */
public class TrustedProxyLoginService extends ContainerLifeCycle implements LoginService {

  private static final Logger LOG = LoggerFactory.getLogger(TrustedProxyLoginService.class);
  public static final boolean READ_ONLY_SUBJECT = true;
  private final CruiseControlAuthorizationService _endUserAuthorizer;
  private final SpnegoLoginServiceWithAuthServiceLifecycle _delegateSpnegoLoginService;
  private final SpnegoLoginServiceWithAuthServiceLifecycle _fallbackSpnegoLoginService;
  private final boolean _fallbackToSpnegoAllowed;

  /**
   * Creates a new instance based on the kerberos realm, the list of trusted proxies, their allowed IP pattern and the
   * {@link CruiseControlAuthorizationService} that stores the end users.
   * @param realm is the kerberos realm of the spnego service principal that is used by Cruise Control
   * @param userAuthorizer authorizes the user that is passed in via the doAs header
   * @param trustedProxies is a list of kerberos service shortnames that identifies the trusted proxies
   * @param trustedProxyIpPattern is a Java regex pattern that defines which IP addresses can be accepted by
   *                              Cruise Control as trusted proxies
   */
  public TrustedProxyLoginService(String realm, CruiseControlAuthorizationService userAuthorizer, List<String> trustedProxies,
                                  String trustedProxyIpPattern, boolean fallbackToSpnegoAllowed, List<String> principalToLocalRules) {
    _delegateSpnegoLoginService = new SpnegoLoginServiceWithAuthServiceLifecycle(
        realm, new TrustedProxyAuthorizationService(trustedProxies, trustedProxyIpPattern), principalToLocalRules);
    _fallbackSpnegoLoginService = new SpnegoLoginServiceWithAuthServiceLifecycle(realm, userAuthorizer, principalToLocalRules);
    _endUserAuthorizer = userAuthorizer;
    _fallbackToSpnegoAllowed = fallbackToSpnegoAllowed;
  }

  // visible for testing
  TrustedProxyLoginService(SpnegoLoginServiceWithAuthServiceLifecycle delegateSpnegoLoginService,
                           SpnegoLoginServiceWithAuthServiceLifecycle fallbackSpnegoLoginService,
                           CruiseControlAuthorizationService userAuthorizer, boolean fallbackToSpnegoAllowed) {
    _delegateSpnegoLoginService = delegateSpnegoLoginService;
    _fallbackSpnegoLoginService = fallbackSpnegoLoginService;
    _endUserAuthorizer = userAuthorizer;
    _fallbackToSpnegoAllowed = fallbackToSpnegoAllowed;
  }

  /**
   * Sets the Kerberos service name used by both the trusted-proxy and fallback SPNEGO login services.
   * @param serviceName Kerberos service name
   */
  public void setServiceName(String serviceName) {
    _delegateSpnegoLoginService.setServiceName(serviceName);
    _fallbackSpnegoLoginService.setServiceName(serviceName);
  }

  /**
   * Sets the Kerberos host name used by both the trusted-proxy and fallback SPNEGO login services.
   * @param hostName Kerberos host name
   */
  public void setHostName(String hostName) {
    _delegateSpnegoLoginService.setHostName(hostName);
    _fallbackSpnegoLoginService.setHostName(hostName);
  }

  /**
   * Sets the keytab path used by both the trusted-proxy and fallback SPNEGO login services.
   * @param path path to the keytab file
   */
  public void setKeyTabPath(Path path) {
    _delegateSpnegoLoginService.setKeyTabPath(path);
    _fallbackSpnegoLoginService.setKeyTabPath(path);
  }

  @Override
  public String getName() {
    return _delegateSpnegoLoginService.getName();
  }

  @Override
  public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getSession) {
    if (request == null) {
      return null;
    }
    String doAsUser = request.getHttpURI() == null ? null : extractDoAs(request);
    if (doAsUser == null && _fallbackToSpnegoAllowed) {
      UserIdentity fallbackIdentity = _fallbackSpnegoLoginService.login(username, credentials, request, getSession);
      if (!(fallbackIdentity instanceof RoleDelegateUserIdentity)
          || !((RoleDelegateUserIdentity) fallbackIdentity).isEstablished()) {
        Principal fallbackPrincipal = fallbackIdentity == null ? null : fallbackIdentity.getUserPrincipal();
        LOG.info("Service user {} isn't authorized as spnego fallback principal",
            fallbackPrincipal == null ? username : fallbackPrincipal.getName());
      }
      return fallbackIdentity;
    } else {
      UserIdentity serviceIdentity = _delegateSpnegoLoginService.login(username, credentials, request, getSession);
      if (serviceIdentity == null || !(serviceIdentity.getUserPrincipal() instanceof SPNEGOUserPrincipal)) {
        return serviceIdentity;
      }
      SPNEGOUserPrincipal servicePrincipal = (SPNEGOUserPrincipal) serviceIdentity.getUserPrincipal();
      LOG.info("Authorizing proxy user {} from {} service", doAsUser, servicePrincipal.getName());
      UserIdentity doAsIdentity = null;
      if (doAsUser != null && !doAsUser.isEmpty()) {
        doAsIdentity = _endUserAuthorizer.getUserIdentity(remoteAddr(request), doAsUser);
      }

      Principal principal = new TrustedProxyPrincipal(doAsUser, servicePrincipal);
      Subject subject = new Subject(READ_ONLY_SUBJECT, Collections.singleton(principal), Collections.emptySet(), Collections.emptySet());

      if (!(serviceIdentity instanceof RoleDelegateUserIdentity)
          || !((RoleDelegateUserIdentity) serviceIdentity).isEstablished()) {
        LOG.info("Service user {} isn't authorized as a trusted proxy", servicePrincipal.getName());
        return new RoleDelegateUserIdentity(subject, principal, null);
      } else {
        if (doAsIdentity == null) {
          LOG.info("Couldn't authorize user {}", doAsUser);
        }
        return new RoleDelegateUserIdentity(subject, principal, doAsIdentity);
      }
    }
  }

  @Override
  public boolean validate(UserIdentity user) {
    return _delegateSpnegoLoginService.validate(user);
  }

  @Override
  public IdentityService getIdentityService() {
    return _delegateSpnegoLoginService.getIdentityService();
  }

  @Override
  public void setIdentityService(IdentityService service) {
    _delegateSpnegoLoginService.setIdentityService(service);
  }

  @Override
  public void logout(UserIdentity user) {
    _delegateSpnegoLoginService.logout(user);
  }

  @Override
  protected void doStart() throws Exception {
    if (_endUserAuthorizer instanceof LifeCycle) {
      ((LifeCycle) _endUserAuthorizer).start();
    }
    _delegateSpnegoLoginService.start();
    _fallbackSpnegoLoginService.start();
    super.doStart();
  }

  @Override
  protected void doStop() throws Exception {
    super.doStop();
    _fallbackSpnegoLoginService.stop();
    _delegateSpnegoLoginService.stop();
    if (_endUserAuthorizer instanceof LifeCycle) {
      ((LifeCycle) _endUserAuthorizer).stop();
    }
  }

  private static String extractDoAs(Request request) {
    // Jetty 12 Request exposes query via HttpURI; keep ParameterUtils.DO_AS name.
    String query = request.getHttpURI().getQuery();
    if (query == null || query.isEmpty()) {
      return null;
    }
    for (String part : query.split("&")) {
      int eq = part.indexOf('=');
      if (eq <= 0) {
        continue;
      }
      String key = part.substring(0, eq);
      if (DO_AS.equals(key)) {
        return java.net.URLDecoder.decode(part.substring(eq + 1), java.nio.charset.StandardCharsets.UTF_8);
      }
    }
    return null;
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
