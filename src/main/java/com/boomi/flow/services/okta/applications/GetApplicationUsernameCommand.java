package com.boomi.flow.services.okta.applications;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.boomi.flow.services.okta.applications.GetApplicationUsername.Input;
import com.boomi.flow.services.okta.applications.GetApplicationUsername.Output;
import com.boomi.flow.services.okta.okta.OktaClientFactory;
import com.google.common.base.Strings;
import com.manywho.sdk.api.run.elements.config.ServiceRequest;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.actions.ActionCommand;
import com.manywho.sdk.services.actions.ActionResponse;
import lombok.experimental.var;
import lombok.val;

import javax.inject.Inject;
import javax.inject.Provider;

public class GetApplicationUsernameCommand implements ActionCommand<ApplicationConfiguration, GetApplicationUsername, Input, Output> {
    private final AuthenticatedWho authenticatedWho;

    @Inject
    public GetApplicationUsernameCommand(Provider<AuthenticatedWho> authenticatedWhoProvider) {
        this.authenticatedWho = authenticatedWhoProvider.get();
    }

    @Override
    public ActionResponse<Output> execute(ApplicationConfiguration configuration, ServiceRequest serviceRequest, Input input) {
        var user = input.getUser();
        if (Strings.isNullOrEmpty(user)) {
            user = authenticatedWho.getUserId();
        }

        val applicationUser = OktaClientFactory.create(configuration)
                .getApplication(input.getApplication())
                .getApplicationUser(user);

        if (applicationUser == null) {
            throw new RuntimeException("No application user could be found with the ID " + user);
        }

        if (applicationUser.getCredentials() == null) {
            throw new RuntimeException("The user with the ID " + user + " does not have any credentials on the chosen application inside Okta");
        }

        return new ActionResponse<>(new Output(applicationUser.getCredentials().getUserName()));
    }
}
