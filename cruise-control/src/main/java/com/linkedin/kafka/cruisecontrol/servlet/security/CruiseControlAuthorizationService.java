/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import org.eclipse.jetty.security.UserIdentity;

/**
 * Cruise Control authorization lookup used after authentication succeeds.
 * <p>
 * Replaces Jetty 9.4 {@code org.eclipse.jetty.security.authentication.AuthorizationService},
 * which was removed in Jetty 12. Resolves role-bearing {@link UserIdentity} for an
 * already-authenticated username (and optional remote address for IP filters).
 */
public interface CruiseControlAuthorizationService {

  /**
   * Resolve roles for an authenticated principal.
   *
   * @param remoteAddr client remote address, or {@code null} when not applicable
   * @param name authenticated username / service name
   * @return identity containing roles, or {@code null} if the user is unknown / not allowed
   */
  UserIdentity getUserIdentity(String remoteAddr, String name);
}
