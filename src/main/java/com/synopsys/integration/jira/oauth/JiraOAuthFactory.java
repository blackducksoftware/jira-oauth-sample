package com.synopsys.integration.jira.oauth;

import com.google.api.client.auth.oauth.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.function.Supplier;

public class JiraOAuthFactory {
    public static final String TEMPORARY_TOKEN_SUFFIX = "/plugins/servlet/oauth/request-token";
    public static final String AUTHORIZATION_URL_SUFFIX = "/plugins/servlet/oauth/authorize";
    public static final String ACCESS_TOKEN_SUFFIX = "/plugins/servlet/oauth/access-token";

    public static final String OUT_OF_BAND_TO_SHOW_TOKEN_SECRET = "oob";

    private String temporaryTokenRequestUrl;
    private String authorizeTemporaryTokenUrl;
    private String accessTokenRequestUrl;

    private KeyFactory rsaKeyFactory;

    public JiraOAuthFactory(String jiraServerUrl) throws NoSuchAlgorithmException {
        temporaryTokenRequestUrl = jiraServerUrl + TEMPORARY_TOKEN_SUFFIX;
        authorizeTemporaryTokenUrl = jiraServerUrl + AUTHORIZATION_URL_SUFFIX;
        accessTokenRequestUrl = jiraServerUrl + ACCESS_TOKEN_SUFFIX;

        rsaKeyFactory = KeyFactory.getInstance("RSA");
    }

    private <T extends AbstractOAuthGetToken> T createTokenWithKeys(Supplier<T> supplier, String consumerKey, String privateKey) throws InvalidKeySpecException {
        T oAuthGetToken = supplier.get();
        oAuthGetToken.consumerKey = consumerKey;
        oAuthGetToken.signer = getOAuthRsaSigner(privateKey);
        return oAuthGetToken;
    }

    public JiraOAuthGetTemporaryToken createJiraOAuthGetTemporaryToken(String consumerKey, String privateKey) throws InvalidKeySpecException {
        JiraOAuthGetTemporaryToken getTemporaryToken = createTokenWithKeys(() -> new JiraOAuthGetTemporaryToken(temporaryTokenRequestUrl), consumerKey, privateKey);
        getTemporaryToken.transport = new NetHttpTransport();
        getTemporaryToken.callback = OUT_OF_BAND_TO_SHOW_TOKEN_SECRET;

        return getTemporaryToken;
    }

    public String getAuthorizationUrl(OAuthCredentialsResponse oAuthCredentialsResponse) {
        OAuthAuthorizeTemporaryTokenUrl authorizationUrl = new OAuthAuthorizeTemporaryTokenUrl(authorizeTemporaryTokenUrl);
        authorizationUrl.temporaryToken = oAuthCredentialsResponse.token;

        return authorizationUrl.toString();
    }

    public JiraOAuthGetAccessToken getJiraOAuthGetAccessToken(String temporaryToken, String verificationCodeFromJira, String consumerKey, String privateKey) throws InvalidKeySpecException {
        JiraOAuthGetAccessToken getAccessToken = createTokenWithKeys(() -> new JiraOAuthGetAccessToken(accessTokenRequestUrl), consumerKey, privateKey);
        getAccessToken.transport = new NetHttpTransport();
        getAccessToken.verifier = verificationCodeFromJira;
        getAccessToken.temporaryToken = temporaryToken;

        return getAccessToken;
    }

    public OAuthParameters getParametersForRequest(String accessToken, String consumerKey, String privateKey) throws InvalidKeySpecException {
        JiraOAuthGetAccessToken getAccessToken = new JiraOAuthGetAccessToken(accessTokenRequestUrl);
        getAccessToken.consumerKey = consumerKey;
        getAccessToken.signer = getOAuthRsaSigner(privateKey);
        getAccessToken.temporaryToken = accessToken;

        return getAccessToken.createParameters();
    }

    private OAuthRsaSigner getOAuthRsaSigner(String privateKeyString) throws InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.decodeBase64(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = rsaKeyFactory.generatePrivate(keySpec);

        OAuthRsaSigner oAuthRsaSigner = new OAuthRsaSigner();
        oAuthRsaSigner.privateKey = privateKey;
        return oAuthRsaSigner;
    }

}
