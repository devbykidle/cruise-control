/*
 * Copyright 2023 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet;

import com.linkedin.kafka.cruisecontrol.config.KafkaCruiseControlConfig;
import com.linkedin.kafka.cruisecontrol.config.constants.WebServerConfig;
import com.linkedin.kafka.cruisecontrol.servlet.security.CruiseControlPropertyUserStore;
import com.linkedin.kafka.cruisecontrol.servlet.security.UserStoreIdentities;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.eclipse.jetty.security.RolePrincipal;
import org.eclipse.jetty.security.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The util class for User Permissions
 */
public class UserPermissionsManager {
    private static final Logger LOG = LoggerFactory.getLogger(UserPermissionsManager.class);

    private final KafkaCruiseControlConfig _config;
    private final Map<String, Set<String>> _rolesPerUsers;

    public UserPermissionsManager(KafkaCruiseControlConfig config) {
        _config = config;
        _rolesPerUsers = createRolesPerUsersMap();
    }

    /**
     * Builds a map between existing users and their roles in Cruise Control
     *
     * @return a map of usernames -> their assigned roles
     */
    private Map<String, Set<String>> createRolesPerUsersMap() {
        Map<String, Set<String>> rolesPerUsers = new HashMap<>();
        boolean securityEnabled = _config.getBoolean(WebServerConfig.WEBSERVER_SECURITY_ENABLE_CONFIG);
        if (securityEnabled) {
            String privilegedFilePath = _config.getString(WebServerConfig.WEBSERVER_AUTH_CREDENTIALS_FILE_CONFIG);
            UserStore userStore = createUserStoreFromFile(privilegedFilePath);
            startUserStore(userStore);

            Set<String> userNames = UserStoreIdentities.knownUserNames(userStore);

            for (String user : userNames) {
                Set<String> roleNames = userStore.getRolePrincipals(user) == null
                        ? new HashSet<>()
                        : userStore.getRolePrincipals(user).stream()
                        .map(RolePrincipal::getName)
                        .map(String::toUpperCase)
                        .collect(Collectors.toSet());
                rolesPerUsers.put(user, roleNames);
            }
            stopUserStore(userStore);
        }
        return rolesPerUsers;
    }

    private void startUserStore(UserStore userStore) {
        try {
            userStore.start();
        } catch (Exception e) {
            LOG.info("UserPermissionsManager user store cannot be started, all permissions queries will contain disallowed roles.");
            LOG.warn("UserPermissionsManager is unable to read the file defined by the following configuration: {}",
                    WebServerConfig.WEBSERVER_AUTH_CREDENTIALS_FILE_CONFIG, e);
        }
    }

    private void stopUserStore(UserStore userStore) {
        try {
            userStore.stop();
        } catch (Exception e) {
            LOG.info("UserPermissionsManager user store cannot be stopped. Exception:\n", e);
        }
    }

    /** Returns the set of roles for a given username
     *
     * @param userName the username
     * @return either Set with roles or an empty set
     */
    public Set<String> getRolesBy(String userName) {
        return _rolesPerUsers.getOrDefault(userName, Collections.emptySet());
    }

    /** Creates UserStore from an external file
     *
     * @param privilegedFilePath a filepath containing user privileges information
     * @return a UserStore object
     */
    private UserStore createUserStoreFromFile(String privilegedFilePath) {
        CruiseControlPropertyUserStore userStore = new CruiseControlPropertyUserStore();
        userStore.setConfig(UserStoreIdentities.resourceFromPath(privilegedFilePath));
        return userStore;
    }
}
