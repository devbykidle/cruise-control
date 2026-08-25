/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security.trustedproxy;

import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlAuthorizationService;
import com.linkedin.kafka.cruisecontrol.servlet.security.DefaultRoleSecurityProvider;
import com.linkedin.kafka.cruisecontrol.servlet.security.SecurityUtils;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreIdentities;
import java.util.List;
import java.util.regex.Pattern;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

/**
 * This authorization service simply checks the incoming user against a list of configured service names maintained in
 * a {@link UserStore} and if specified, the remote IP address against a configured pattern.
 */
public class TrustedProxyAuthorizationService extends AbstractLifeCycle implements CruiseControlAuthorizationService {

  private final UserStore _serviceUserStore;
  private final Pattern _trustedProxyIpPattern;

  TrustedProxyAuthorizationService(List<String> userNames, String trustedProxyIpPattern) {
    _serviceUserStore = new UserStore();
    userNames.forEach(u -> _serviceUserStore.addUser(u, SecurityUtils.NO_CREDENTIAL, new String[] { DefaultRoleSecurityProvider.ADMIN }));
    if (trustedProxyIpPattern != null) {
      _trustedProxyIpPattern = Pattern.compile(trustedProxyIpPattern);
    } else {
      _trustedProxyIpPattern = null;
    }
  }

  @Override
  public UserIdentity getUserIdentity(String remoteAddr, String name) {
    // SPNEGO may pass names in servicename/host format but we only store the servicename
    int nameHostSeparatorIndex = name.indexOf('/');
    String serviceName = nameHostSeparatorIndex > 0 ? name.substring(0, nameHostSeparatorIndex) : name;
    UserIdentity serviceIdentity = UserStoreIdentities.getUserIdentity(_serviceUserStore, serviceName);
    if (_trustedProxyIpPattern != null) {
      if (remoteAddr == null || !_trustedProxyIpPattern.matcher(remoteAddr).matches()) {
        return null;
      }
      return serviceIdentity;
    } else {
      return serviceIdentity;
    }
  }

  @Override
  protected void doStart() throws Exception {
    _serviceUserStore.start();
    super.doStart();
  }

  @Override
  protected void doStop() throws Exception {
    super.doStop();
    _serviceUserStore.stop();
  }
}
