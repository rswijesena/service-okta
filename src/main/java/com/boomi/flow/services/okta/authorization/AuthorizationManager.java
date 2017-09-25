package com.boomi.flow.services.okta.authorization;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.boomi.flow.services.okta.oauth2.OktaApi20Factory;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.manywho.sdk.services.types.TypeBuilder;
import com.manywho.sdk.services.types.system.$User;
import lombok.experimental.var;

import java.util.HashMap;

public class AuthorizationManager {
    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;

    @Inject
    public AuthorizationManager(ConfigurationParser configurationParser, TypeBuilder typeBuilder) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
    }

    public ObjectDataResponse authorization(AuthenticatedWho authenticatedWho, ObjectDataRequest request) {
        String status;

        switch (request.getAuthorization().getGlobalAuthenticationType()) {
            case AllUsers:
                // If it's a public user (i.e. not logged in) then return a 401
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    status = "401";
                } else {
                    status = "200";
                }

                break;
            case Public:
                status = "200";
                break;
            case Specified:
                throw new UnsupportedOperationException("Using the Specified authentication type isn't supported");
            default:
                status = "401";
                break;
        }

        ApplicationConfiguration configuration = configurationParser.from(request);

        OAuth20Service service = OktaApi20Factory.create(configuration);

        var additionalParameters = new HashMap<String, String>();

        // If we're given an identity provider ID, we set that as the provider to log into
        if (Strings.isNullOrEmpty(configuration.getIdentityProvider()) == false) {
            additionalParameters.put("idp", configuration.getIdentityProvider());
        }

        var user = new $User();
        user.setDirectoryId("Okta");
        user.setDirectoryName("Okta");
        user.setAuthenticationType(AuthorizationType.Oauth2);
        user.setLoginUrl(service.getAuthorizationUrl(additionalParameters));
        user.setStatus(status);
        user.setUserId("");

        return new ObjectDataResponse(typeBuilder.from(user));
    }
}
