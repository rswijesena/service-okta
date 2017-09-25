package com.boomi.flow.services.okta.authorization;

import com.google.inject.Provider;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.controllers.AbstractAuthorizationController;

import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

@Path("/authorization")
public class AuthorizationController extends AbstractAuthorizationController {
    private final AuthorizationManager manager;
    private final Provider<AuthenticatedWho> authenticatedWhoProvider;


    @Inject
    public AuthorizationController(AuthorizationManager manager, Provider<AuthenticatedWho> authenticatedWhoProvider) {
        this.manager = manager;
        this.authenticatedWhoProvider = authenticatedWhoProvider;
    }

    @POST
    @Override
    public ObjectDataResponse authorization(ObjectDataRequest objectDataRequest) throws Exception {
        return manager.authorization(authenticatedWhoProvider.get(), objectDataRequest);
    }
}