package com.haulmont.addon.oidc.service;

import com.haulmont.addon.oidc.config.OidcConfig;
import com.haulmont.cuba.core.global.CommitContext;
import com.haulmont.cuba.core.global.Configuration;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.security.entity.Group;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.entity.UserRole;
import com.haulmont.cuba.security.role.RoleDefinition;
import com.haulmont.cuba.security.role.RolesService;
import org.springframework.stereotype.Service;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(OidcRegistrationService.NAME)
public class OidcRegistrationServiceBean implements OidcRegistrationService {

    @Inject
    private Configuration configuration;
    @Inject
    private DataManager dataManager;
    @Inject
    private RolesService rolesService;

    @Inject
    private OidcService oidcService;

    @Override
    public User findOrRegisterUser(OidcService.OidcAccessData userData) {
        //User existingUser = oidcService.findUserByUsername(userData.getSub());
        User existingUser = oidcService.findUserByUsername(userData.getPreferredUsername());

        if (existingUser != null) {
            OidcConfig config = configuration.getConfig(OidcConfig.class);
            if (config.getRefreshRoles() != null && !"".equals(config.getRefreshRoles())) {
                CommitContext context = new CommitContext();
                context.setRemoveInstances(existingUser.getUserRoles());
                List<UserRole> userRoleList = getNewUserRoleList(existingUser, userData);
                context.setCommitInstances(userRoleList);
                dataManager.commit(context);
                return dataManager.reload(existingUser, "user.edit");
            }
            return existingUser;
        }

        String email = userData.getEmail();
        User user = dataManager.create(User.class);
        String username = userData.getPreferredUsername();
        user.setLogin(username);
        user.setName(username);
        user.setGroup(getDefaultGroup());
        user.setActive(true);
        user.setEmail(email);
        user.setDisabledDefaultRoles(true);

        List<UserRole> userRoleList = getNewUserRoleList(user, userData);

        CommitContext context = new CommitContext();
        context.setCommitInstances(userRoleList);
        context.addInstanceToCommit(user);

        return dataManager.commit(context).get(user);
    }

    private List<UserRole> getNewUserRoleList(User user, OidcService.OidcAccessData userData) {
        List<UserRole> roles = new ArrayList<>();
        if (userData.getRoles() != null && !userData.getRoles().isEmpty()) {
            for (String roleName : userData.getRoles()) {
                RoleDefinition roleDefinition = rolesService.getRoleDefinitionByName(roleName);

                if (roleDefinition != null) {
                    UserRole userRole = dataManager.create(UserRole.class);
                    userRole.setRoleName(roleDefinition.getName());
                    userRole.setUser(user);

                    roles.add(userRole);
                }
            }
        }
        OidcConfig config = configuration.getConfig(OidcConfig.class);
        if (config.getDefaultRoles()!= null && !config.getDefaultRoles().isEmpty()) {
            List<String> roleNames = Arrays.asList(config.getDefaultRoles().split(","))
                    .stream().map(r -> r.trim()).collect(Collectors.toList());
            for (String roleName : roleNames) {
                RoleDefinition roleDefinition = rolesService.getRoleDefinitionByName(roleName);

                if (roleDefinition != null) {
                    UserRole userRole = dataManager.create(UserRole.class);
                    userRole.setRoleName(roleDefinition.getName());
                    userRole.setUser(user);

                    roles.add(userRole);
                }
            }
        }
        return roles;
    }

    private Group getDefaultGroup() {
        OidcConfig config = configuration.getConfig(OidcConfig.class);

        return dataManager.load(Group.class)
                .query("select g from sec$Group g where g.id = :defaultGroupId")
                .parameter("defaultGroupId", UUID.fromString(config.getDefaultGroupId()))
                .one();
    }
}