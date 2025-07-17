package com.haulmont.addon.oidc.config;

import com.haulmont.cuba.core.config.Config;
import com.haulmont.cuba.core.config.Property;
import com.haulmont.cuba.core.config.Source;
import com.haulmont.cuba.core.config.SourceType;
import com.haulmont.cuba.core.config.defaults.Default;

@Source(type = SourceType.APP)
public interface OidcConfig extends Config {

    @Default("0fa2b1a5-1d68-4d69-9fbd-dff348347f93")
    @Property("oidc.defaultGroupId")
    String getDefaultGroupId();

    @Default("system-full-access")
    @Property("oidc.defaultRoleCode")
    String getDefaultRoleCode();

    @Property("oidc.realm")
    String getKeycloakRealm();

    @Property("oidc.clientId")
    String getOidcClientId();

    @Property("oidc.clientSecret")
    String getOidcClientSecret();

    @Property("oidc.baseUrl")
    String getBaseUrl();
}
