/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.RolePrincipal;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.resource.ResourceFactory;

/**
 * Helpers to build Jetty 12 {@link UserIdentity} objects from {@link UserStore},
 * which no longer exposes {@code getUserIdentity}/{@code getKnownUserIdentities}.
 */
public final class UserStoreIdentities {

  private UserStoreIdentities() {
  }

  /**
   * Build a {@link UserIdentity} for {@code name} from the given store, or {@code null} if unknown.
   *
   * @param userStore the Jetty user store
   * @param name username to resolve
   * @return identity with roles, or {@code null} if the user is unknown
   */
  public static UserIdentity getUserIdentity(UserStore userStore, String name) {
    UserPrincipal userPrincipal = userStore.getUserPrincipal(name);
    if (userPrincipal == null) {
      return null;
    }
    List<RolePrincipal> rolePrincipals = userStore.getRolePrincipals(name);
    if (rolePrincipals == null) {
      rolePrincipals = Collections.emptyList();
    }

    Subject subject = new Subject();
    userPrincipal.configureSubject(subject);
    String[] roles = new String[rolePrincipals.size()];
    int i = 0;
    for (RolePrincipal rolePrincipal : rolePrincipals) {
      rolePrincipal.configureForSubject(subject);
      roles[i++] = rolePrincipal.getName();
    }
    subject.setReadOnly();
    return UserIdentity.from(subject, userPrincipal, roles);
  }

  /**
   * Known usernames in a {@link UserStore}. Prefer {@link EnumerableUserStore}; otherwise returns empty set.
   *
   * @param userStore the Jetty user store
   * @return known usernames, or an empty set when enumeration is unsupported
   */
  public static Set<String> knownUserNames(UserStore userStore) {
    if (userStore instanceof EnumerableUserStore) {
      return ((EnumerableUserStore) userStore).knownUserNames();
    }
    return Collections.emptySet();
  }

  /**
   * Create a Jetty {@link Resource} for a filesystem path (credentials / privileges file).
   *
   * @param path filesystem path to the credentials or privileges file
   * @return Jetty resource for the path
   */
  public static Resource resourceFromPath(String path) {
    return ResourceFactory.root().newResource(path);
  }

  /**
   * Marker for user stores that can enumerate known usernames without reflection.
   */
  public interface EnumerableUserStore {
    Set<String> knownUserNames();
  }
}
