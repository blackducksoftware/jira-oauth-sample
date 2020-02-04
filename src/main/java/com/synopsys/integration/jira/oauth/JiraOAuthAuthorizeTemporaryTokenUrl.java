package com.synopsys.integration.jira.oauth;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.util.Key;

public class JiraOAuthAuthorizeTemporaryTokenUrl extends GenericUrl {
    @Key("oauth_token")
    public String temporaryToken;

    public JiraOAuthAuthorizeTemporaryTokenUrl(String authorizeTemporaryTokenUrl) {
        super(authorizeTemporaryTokenUrl);
    }

}
