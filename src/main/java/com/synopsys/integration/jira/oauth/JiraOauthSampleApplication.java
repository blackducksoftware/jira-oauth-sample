package com.synopsys.integration.jira.oauth;

import com.google.api.client.auth.oauth.OAuthCredentialsResponse;
import com.google.api.client.auth.oauth.OAuthParameters;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

@SpringBootApplication
public class JiraOauthSampleApplication implements ApplicationRunner {
    private Logger logger = LoggerFactory.getLogger(JiraOauthSampleApplication.class);

    public static final String jiraBaseUrl = "";
    public static final String projectApi = jiraBaseUrl + "/rest/api/2/project/search";

    public static final String CONSUMER_KEY = "";
    public static final String PRIVATE_KEY = "";

    public static final String TEMPORARY_TOKEN = "";
    public static final String VERIFICATION_CODE_FROM_JIRA = "";

    public static final String ACCESS_TOKEN = "";

    public static void main(final String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder(JiraOauthSampleApplication.class);
        builder.run(args);
    }

    @Override
    public void run(final ApplicationArguments applicationArguments) throws Exception {
        JiraOAuthFactory jiraOAuthFactory = new JiraOAuthFactory(jiraBaseUrl);

        if (applicationArguments.containsOption("auth")) {
            getAuthorizationUrl(jiraOAuthFactory);
        } else if (applicationArguments.containsOption("access")) {
            getAccessToken(jiraOAuthFactory, TEMPORARY_TOKEN, VERIFICATION_CODE_FROM_JIRA);
        } else if (applicationArguments.containsOption("request")) {
            performRequest(jiraOAuthFactory);
        }
    }

    private void getAuthorizationUrl(JiraOAuthFactory jiraOAuthFactory) throws InvalidKeySpecException, IOException {
        JiraOAuthGetTemporaryToken getTemporaryToken = jiraOAuthFactory.createJiraOAuthGetTemporaryToken(CONSUMER_KEY, PRIVATE_KEY);

        OAuthCredentialsResponse oAuthCredentialsResponse = getTemporaryToken.execute();
        System.out.println("Token: " + oAuthCredentialsResponse.token);
        System.out.println("Token Secret: " + oAuthCredentialsResponse.tokenSecret);
        System.out.println("callback confirmed: " + oAuthCredentialsResponse.callbackConfirmed);

        String authorizationUrl = jiraOAuthFactory.getAuthorizationUrl(oAuthCredentialsResponse);
        System.out.println("authorization url: " + authorizationUrl);
    }

    private void getAccessToken(JiraOAuthFactory jiraOAuthFactory, String temporaryToken, String verificationCodeFromJira) throws InvalidKeySpecException, IOException {
        JiraOAuthGetAccessToken oAuthAccessToken = jiraOAuthFactory.getJiraOAuthGetAccessToken(temporaryToken, verificationCodeFromJira, CONSUMER_KEY, PRIVATE_KEY);
        OAuthCredentialsResponse response = oAuthAccessToken.execute();

        System.out.println("Access token:" + response.token);
    }

    private void performRequest(JiraOAuthFactory jiraOAuthFactory) throws InvalidKeySpecException, IOException {
        OAuthParameters oAuthParameters = jiraOAuthFactory.getParametersForRequest(ACCESS_TOKEN, CONSUMER_KEY, PRIVATE_KEY);

        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory(oAuthParameters);
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(projectApi));
        HttpResponse response = request.execute();
        Scanner s = new Scanner(response.getContent()).useDelimiter("\\A");
        String result = s.hasNext() ? s.next() : "";
        System.out.println(result);
    }

}
