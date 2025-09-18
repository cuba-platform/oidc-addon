package com.haulmont.addon.oidc.service;


import com.google.gson.annotations.SerializedName;
import com.haulmont.cuba.security.entity.User;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.Serializable;
import java.util.List;

public interface OidcService {
    String NAME = "oidc_OidcService";

    String getLoginUrl(String appUrl, OAuth2ResponseType responseType);

    void logout(String keycloakId);

    OidcAccessData getAccessData(OidcToken oidcToken);

    OidcRefreshData getRefreshData(OidcToken oidcToken);

    OidcToken getOidcToken(String appUrl, String code);

    User findUserByUsername(String username);

    OidcAccessData validateAndParseToken(String token);


    enum OAuth2ResponseType {
        CODE("code"),
        TOKEN("token"),
        CODE_TOKEN("code%20token");

        private final String id;

        OAuth2ResponseType(String id) {
            this.id = id;
        }

        public String getId() {
            return id;
        }
    }

    class OidcToken implements Serializable {

        @SerializedName("access_token")
        private String accessToken;
        @SerializedName("refresh_token")
        private String refreshToken;

        public OidcToken() {
        }

        public OidcToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }

    class OidcRefreshData implements Serializable {

        private Long exp;

        public Long getExp() {
            return exp;
        }

        public void setExp(Long exp) {
            this.exp = exp;
        }

        @Override
        public String toString() {
            return "OidcRefreshData{" +
                   "exp=" + exp +
                   '}';
        }
    }

    class OidcAccessData implements Serializable {

        private String sub;
        private String email;
        private String name;

        private String preferred_username;

        private Long exp;
        private List<String> roles;

        public OidcAccessData(String sub, String email, String name, String preferred_username, Long exp, List<String> roles) {
            this.sub = sub;
            this.email = email;
            this.name = name;
            this.preferred_username = preferred_username;
            this.exp = exp;
            this.roles = roles;
        }

        public String getSub() {
            return sub;
        }

        public String getEmail() {
            return email;
        }

        public String getName() {
            return name;
        }

        public String getPreferredUsername() {
            return preferred_username;
        }

        public Long getExp() {
            return exp;
        }

        public void setExp(Long exp) {
            this.exp = exp;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        @Override
        public String toString() {
            return "OidcAccessData{" +
                   "sub='" + sub + '\'' +
                   ", email='" + email + '\'' +
                   ", name='" + name + '\'' +
                   ", preferred_username='" + preferred_username  + '\'' +
                   ", exp=" + exp +
                   ", roles=" + roles +
                   '}';
        }
    }
}