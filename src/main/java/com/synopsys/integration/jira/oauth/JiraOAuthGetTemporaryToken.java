package com.synopsys.integration.jira.oauth;

import com.google.api.client.auth.oauth.OAuthGetTemporaryToken;

public class JiraOAuthGetTemporaryToken extends OAuthGetTemporaryToken {
    public JiraOAuthGetTemporaryToken(String temporaryTokenRequestUrl) {
        super(temporaryTokenRequestUrl);
        this.usePost = true;
    }

}
