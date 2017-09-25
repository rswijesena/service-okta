package com.boomi.flow.services.okta.okta;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;

public class OktaClientFactory {
    public static Client create(ApplicationConfiguration configuration) {
        return Clients.builder()
                .setOrgUrl("https://" + configuration.getOrganizationUrl())
                .setClientCredentials(new TokenClientCredentials(configuration.getApiKey()))
                .build();
    }
}
