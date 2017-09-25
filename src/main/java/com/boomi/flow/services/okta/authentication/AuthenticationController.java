package com.boomi.flow.services.okta.authentication;

import com.manywho.sdk.api.security.AuthenticatedWhoResult;
import com.manywho.sdk.api.security.AuthenticationCredentials;
import com.manywho.sdk.services.controllers.AbstractAuthenticationController;

import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

@Path("/authentication")
public class AuthenticationController extends AbstractAuthenticationController {
    private final AuthenticationManager manager;

    @Inject
    public AuthenticationController(AuthenticationManager manager) {
        this.manager = manager;
    }

    @POST
    @Override
    public AuthenticatedWhoResult authentication(AuthenticationCredentials credentials) throws Exception {
        return manager.authentication(credentials);
    }
}
