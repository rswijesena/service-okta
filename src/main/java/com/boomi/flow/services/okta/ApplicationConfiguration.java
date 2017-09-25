package com.boomi.flow.services.okta;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.configuration.Configuration;

public class ApplicationConfiguration implements Configuration {
    @Configuration.Setting(name = "Client ID", contentType = ContentType.String)
    private String clientId;

    @Configuration.Setting(name = "Client Secret", contentType = ContentType.Password)
    private String clientSecret;

    @Configuration.Setting(name = "Identity Provider ID", contentType = ContentType.String, required = false)
    private String identityProvider;

    @Configuration.Setting(name = "Organization URL", contentType = ContentType.String)
    private String organizationUrl;

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getIdentityProvider() {
        return identityProvider;
    }

    public String getOrganizationUrl() {
        return organizationUrl;
    }
}
