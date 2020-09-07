package com.boomi.flow.services.okta.okta;

import com.github.scribejava.core.builder.api.DefaultApi20;

public class OktaApi20 extends DefaultApi20 {
    private final String organization;

    public OktaApi20(String organization) {
        this.organization = organization;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return String.format("https://%s/oauth/token", organization);
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return String.format("https://%s/authorize", organization);
    }
}
