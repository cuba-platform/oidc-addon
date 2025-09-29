package com.haulmont.addon.oidc.service;

import com.haulmont.addon.oidc.config.OidcConfig;
//import com.haulmont.addon.oidc.entity.KeycloakUser;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.haulmont.bali.util.URLEncodeUtils;
import com.haulmont.cuba.core.global.Configuration;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.security.app.UserSessionsAPI;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.UserSession;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import java.io.IOException;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.text.ParseException;

@Service(OidcService.NAME)
public class OidcServiceBean implements OidcService {

    private static final String OIDC_AUTH_ENDPOINT = "%s/realms/%s/protocol/openid-connect/auth?%s";
    private static final String OIDC_ACCESS_TOKEN_PATH = "%s/realms/%s/protocol/openid-connect/token";
    private static final String OIDC_LOGOUT_PATH = "%s/realms/%s/protocol/openid-connect/logout";

    private static Gson gson;

    @Inject
    private UserSessionsAPI userSessionsAPI;
    @Inject
    private Configuration configuration;
    @Inject
    private DataManager dataManager;

    @PostConstruct
    private void init() {
        gson = new GsonBuilder()
                .setLenient()
                .create();
    }

    private static String encode(String s) {
        return URLEncodeUtils.encodeUtf8(s);
    }

    @Override
    public String getLoginUrl(String appUrl, OAuth2ResponseType responseType) {
        OidcConfig config = configuration.getConfig(OidcConfig.class);
        String webAppUrl = appUrl != null ? appUrl : configuration.getConfig(GlobalConfig.class).getWebAppUrl();

        String params = getAuthParams(config.getOidcClientId(), webAppUrl);
        String baseUrl = config.getBaseUrl();
        String realm = config.getKeycloakRealm();

        return String.format(OIDC_AUTH_ENDPOINT, baseUrl, realm, params);
    }

    @Override
    public String getLogoutUrl() {
        OidcConfig config = configuration.getConfig(OidcConfig.class);

        String baseUrl = config.getBaseUrl();
        String realm = config.getKeycloakRealm();

        return String.format(OIDC_LOGOUT_PATH, baseUrl, realm);
    }

    public User findUserByUsername(String username) {
        return dataManager.load(User.class)
                .query("select u from sec$User u where lower(u.login) = :username or lower(u.login) = :username")
                .parameter("username", username)
                .view("user.edit")
                .optional()
                .orElse(null);
    }

    @Override
    public void logout(String username) {
        User existingUser = findUserByUsername(username);

        if (existingUser != null) {
            List<UserSession> userSessions = userSessionsAPI.getUserSessionsStream()
                    .filter(session -> session.getUser().getId().equals(existingUser.getId()))
                    .collect(Collectors.toList());

            for (UserSession userSession : userSessions) {
                userSessionsAPI.killSession(userSession.getId());
            }
        }
    }

    @Override
    public OidcRefreshData getRefreshData(OidcToken oidcToken) {
        return parseExpiredDate(oidcToken);
    }

    @Override
    public OidcAccessData getAccessData(OidcToken oidcToken) {
        return parseUserData(oidcToken);
    }

    @Override
    public OidcToken getOidcToken(String appUrl, String authCode) {
        OidcConfig oidcConfig = configuration.getConfig(OidcConfig.class);

        String realm = oidcConfig.getKeycloakRealm();
        String clientId = oidcConfig.getOidcClientId();
        String clientSecret = oidcConfig.getOidcClientSecret();
        String baseUrl = oidcConfig.getBaseUrl();
        String redirectUri = appUrl != null ? appUrl : configuration.getConfig(GlobalConfig.class).getWebAppUrl();

        HttpPost tokenRequest = new HttpPost(String.format(OIDC_ACCESS_TOKEN_PATH, baseUrl, realm));

        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
        urlParameters.add(new BasicNameValuePair("code", authCode));
        urlParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));

        if (clientSecret != null) {
            urlParameters.add(new BasicNameValuePair("client_secret", clientSecret));
        }
        urlParameters.add(new BasicNameValuePair("client_id", clientId));
        urlParameters.add(new BasicNameValuePair("redirect_uri", redirectUri));

        tokenRequest.setEntity(new UrlEncodedFormEntity(urlParameters, Charset.defaultCharset()));

        tokenRequest.setHeader(HttpHeaders.ACCEPT, MediaType.ALL_VALUE);
        String response = performRequest(tokenRequest);
        return gson.fromJson(response, OidcToken.class);
    }

    private String getAuthParams(String clientId, String redirectUri) {
        return "client_id=" + clientId +
                "&scope=openid" +
                "&response_type=code" +
                "&redirect_uri=" + encode(redirectUri);
    }


    private String performRequest(HttpRequestBase request) {
        HttpClientConnectionManager cm = new BasicHttpClientConnectionManager();
        HttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(cm)
                .build();
        try {
            HttpResponse httpResponse = httpClient.execute(request);
            if (httpResponse.getStatusLine().getStatusCode() != 200) {
                throw new RuntimeException("Unable to perform request. Response HTTP status: "
                        + httpResponse.getStatusLine().getStatusCode());
            }
            return EntityUtils.toString(httpResponse.getEntity());
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        } finally {
            request.releaseConnection();
        }
    }

    public OidcRefreshData parseExpiredDate(OidcToken oidcToken) {
        String refreshToken = oidcToken.getRefreshToken();
        String[] chunks = refreshToken.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String payload = new String(decoder.decode(chunks[1]));

        return gson.fromJson(payload, OidcRefreshData.class);
    }

    public OidcAccessData parseUserData(OidcToken oidcToken) {
        String accessToken = oidcToken.getAccessToken();
        String[] chunks = accessToken.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String payload = new String(decoder.decode(chunks[1]));

        return gson.fromJson(payload, OidcAccessData.class);
    }

    public OidcAccessData validateAndParseToken(String token) {
        String[] chunks = token.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String payload = new String(decoder.decode(chunks[1]));

        return gson.fromJson(payload, OidcAccessData.class);
    }


}