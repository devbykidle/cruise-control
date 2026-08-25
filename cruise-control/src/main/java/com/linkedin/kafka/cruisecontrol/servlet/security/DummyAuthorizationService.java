/*
 * Copyright 2023 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import java.security.Principal;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.RoleDelegateUserIdentity;
import org.eclipse.jetty.security.SPNEGOUserPrincipal;
import org.eclipse.jetty.security.UserIdentity;

/**
 * Authorization stub used when SPNEGO authentication has succeeded but roles are assigned later
 * by Cruise Control wrappers. Returns a non-established {@link RoleDelegateUserIdentity}.
 */
public class DummyAuthorizationService implements CruiseControlAuthorizationService {

  @Override
  public UserIdentity getUserIdentity(String remoteAddr, String name) {
    return createUserIdentity(name);
  }

  private UserIdentity createUserIdentity(String username) {
    Principal userPrincipal = new SPNEGOUserPrincipal(username, "");
    Subject subject = new Subject();
    subject.getPrincipals().add(userPrincipal);
    subject.getPrivateCredentials().add(SecurityUtils.NO_CREDENTIAL);
    subject.setReadOnly();
    return new RoleDelegateUserIdentity(subject, userPrincipal, null);
  }
}
