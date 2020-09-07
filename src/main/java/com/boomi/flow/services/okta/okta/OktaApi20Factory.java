package com.boomi.flow.services.okta.okta;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

public class OktaApi20Factory {
    public static OAuth20Service create(ApplicationConfiguration configuration) {
        return new ServiceBuilder(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())

                .scope("openid email profile")
                .build(new OktaApi20(configuration.getOrganizationUrl()));
    }
    public static OAuth20Service createTokenFactory(ApplicationConfiguration configuration) {
        return new ServiceBuilder(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback("https://flow.manywho.com/api/run/1/oauth2")
                .scope("openid email profile")
                .build(new OktaApi20(configuration.getOrganizationUrl()));
    }
}
