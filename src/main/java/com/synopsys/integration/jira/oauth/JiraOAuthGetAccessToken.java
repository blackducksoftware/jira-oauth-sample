package com.synopsys.integration.jira.oauth;

import com.google.api.client.auth.oauth.OAuthGetAccessToken;

public class JiraOAuthGetAccessToken extends OAuthGetAccessToken {
    public JiraOAuthGetAccessToken(String accessTokenRequestUrl) {
        super(accessTokenRequestUrl);
        this.usePost = true;
    }

}
