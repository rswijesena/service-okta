package com.boomi.flow.services.okta.authentication;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.boomi.flow.services.okta.okta.OktaApi20Factory;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import javax.inject.Inject;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class AuthenticationManager {
    private final ConfigurationParser configurationParser;

    @Inject
    public AuthenticationManager(ConfigurationParser configurationParser) {
        this.configurationParser = configurationParser;
    }

    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials) {
        ApplicationConfiguration configuration = configurationParser.from(credentials);

        OAuth2AccessToken token;

        try {
            // Request an access token from Okta using the given authorization code
            token = OktaApi20Factory.create(configuration)
                        .getAccessToken(credentials.getCode());
        } catch (IOException | InterruptedException | ExecutionException e) {
            throw new RuntimeException("Unable to get the access token from Okta: " + e.getMessage(), e);
        }

        if (token == null) {
            throw new RuntimeException("An empty access token was given back from Okta");
        }

        HttpResponse<JsonNode> response;

        try {
            // Request the user's profile from Okta
            response = Unirest.post(String.format("https://%s/oauth2/v1/userinfo", configuration.getOrganizationUrl()))
                    .header("Authorization", "Bearer " + token.getAccessToken())
                    .asJson();
        } catch (UnirestException e) {
            throw new RuntimeException("Unable to fetch the user from Okta: " + e.getMessage(), e);
        }

        // Build up the profile result from the information Okta gives us
        AuthenticatedWhoResult result = new AuthenticatedWhoResult();
        result.setDirectoryId("okta");
        result.setDirectoryName("Okta");
        result.setEmail(response.getBody().getObject().getString("email"));
        result.setFirstName(response.getBody().getObject().getString("given_name"));
        result.setIdentityProvider("?");
        result.setLastName(response.getBody().getObject().getString("family_name"));
        result.setStatus(AuthenticatedWhoResult.AuthenticationStatus.Authenticated);
        result.setTenantName("?");
        result.setToken(token.getAccessToken());
        result.setUserId(response.getBody().getObject().getString("sub"));
        result.setUsername(response.getBody().getObject().getString("email"));

        return result;
    }
}
