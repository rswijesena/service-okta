package com.boomi.flow.services.okta.authorization;

import com.boomi.flow.services.okta.ApplicationConfiguration;
import com.boomi.flow.services.okta.okta.OktaApi20Factory;
import com.boomi.flow.services.okta.okta.OktaClientFactory;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.manywho.sdk.api.AuthorizationType;
import com.manywho.sdk.api.run.elements.config.Group;
import com.manywho.sdk.api.run.elements.type.MObject;
import com.manywho.sdk.api.run.elements.type.ObjectDataRequest;
import com.manywho.sdk.api.run.elements.type.ObjectDataResponse;
import com.manywho.sdk.api.run.elements.type.Property;
import com.manywho.sdk.api.security.AuthenticatedWho;
import com.manywho.sdk.services.configuration.ConfigurationParser;
import com.manywho.sdk.services.types.TypeBuilder;
import com.manywho.sdk.services.types.system.$User;
import com.manywho.sdk.services.types.system.AuthorizationAttribute;
import com.manywho.sdk.services.types.system.AuthorizationGroup;
import com.manywho.sdk.services.types.system.AuthorizationUser;
import com.manywho.sdk.services.utils.Streams;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.user.User;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizationManager {
    private final ConfigurationParser configurationParser;
    private final TypeBuilder typeBuilder;

    @Inject
    public AuthorizationManager(ConfigurationParser configurationParser, TypeBuilder typeBuilder) {
        this.configurationParser = configurationParser;
        this.typeBuilder = typeBuilder;
    }

    public ObjectDataResponse authorization(AuthenticatedWho authenticatedWho, ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        Client client = Clients.builder()
                .setClientCredentials(new TokenClientCredentials(configuration.getApiKey()))
                .setOrgUrl("https://" + configuration.getOrganizationUrl())
                .build();

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
                if (authenticatedWho.getUserId().equals("PUBLIC_USER")) {
                    status = "401";
                    break;
                }

                User user = client.getUser(authenticatedWho.getUserId());
                if (user == null) {
                    status = "401";
                    break;
                }

                // We need to check if the authenticated user is one of the authorized users by ID
                if (request.getAuthorization().hasUsers()) {
                    boolean isAuthorized = request.getAuthorization().getUsers().stream()
                            .anyMatch(u -> u.getAuthenticationId().equals(user.getId()));

                    if (isAuthorized) {
                        status = "200";
                    } else {
                        status = "401";
                    }

                    break;
                }

                // We need to check if the authenticated user is a member of one of the given groups, by group ID
                if (request.getAuthorization().hasGroups()) {
                    // If the user is a member of no groups, then they're automatically not authorized
                    if (user.listGroups() == null) {
                        status = "401";
                        break;
                    }

                    List<Group> authorizedGroups = request.getAuthorization().getGroups();

                    boolean isAuthorized = Streams.asStream(user.listGroups())
                            .anyMatch(group -> authorizedGroups.stream().anyMatch(g -> g.getAuthenticationId().equals(group.getId())));

                    if (isAuthorized) {
                        status = "200";
                    } else {
                        status = "401";
                    }

                    break;
                }
            default:
                status = "401";
                break;
        }

        OAuth20Service service = OktaApi20Factory.create(configuration);

        Map<String, String> additionalParameters = new HashMap<String, String>();

        // If we're given an identity provider ID, we set that as the provider to log into
        if (Strings.isNullOrEmpty(configuration.getIdentityProvider()) == false) {
            additionalParameters.put("idp", configuration.getIdentityProvider());
        }

        $User user = new $User();
        user.setDirectoryId("Okta");
        user.setDirectoryName("Okta");
        user.setAuthenticationType(AuthorizationType.Oauth2);
        user.setLoginUrl(service.getAuthorizationUrl(additionalParameters));
        user.setStatus(status);
        user.setUserId("");

        return new ObjectDataResponse(typeBuilder.from(user));
    }

    public ObjectDataResponse groupAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("member", "Member"))
        );
    }

    public ObjectDataResponse groups(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        Client client = OktaClientFactory.create(configuration);

        // Build the required AuthorizationGroup objects out of the groups that Okta tells us about
        List<AuthorizationGroup> groups = Streams.asStream(client.listGroups(null, buildFilterStringFromRequest(request, "GroupAuthorizationGroup", "AuthenticationId"), null).iterator())
                .map(group -> new AuthorizationGroup(group.getId(), group.getProfile().getName(), group.getProfile().getDescription()))
                .collect(Collectors.toList());

        return new ObjectDataResponse(
                typeBuilder.from(groups)
        );
    }

    private String buildFilterStringFromRequest(ObjectDataRequest objectDataRequest, String name, String propertyName){

        String filter = "";

        if (objectDataRequest.getObjectData() != null && objectDataRequest.getObjectData().size() > 0) {
            for (MObject requestedGroup : objectDataRequest.getObjectData()) {
                if (requestedGroup.getDeveloperName().equals(name)) {

                    String idToSearch = requestedGroup.getProperties().stream()
                            .filter(property -> property.getDeveloperName().equals(propertyName))
                            .findFirst()
                            .orElse(new Property(propertyName, ""))
                            .getContentValue();

                    if(filter != ""){
                        filter += " or ";
                    }

                    filter += "id eq \"" + idToSearch + "\"";
                }
            }
        }

        return filter;
    }

    public ObjectDataResponse userAttributes() {
        return new ObjectDataResponse(
                typeBuilder.from(new AuthorizationAttribute("user", "User"))
        );
    }

    public ObjectDataResponse users(ObjectDataRequest request) {
        ApplicationConfiguration configuration = configurationParser.from(request);

        Client client = OktaClientFactory.create(configuration);

        // Build the required AuthorizationUser objects out of the users that Okta tells us about
        List<AuthorizationUser> users = Streams.asStream(client.listUsers(null, buildFilterStringFromRequest(request, "GroupAuthorizationUser", "AuthenticationId"), null, null, null).iterator())
                .map(user -> new AuthorizationUser(
                        user.getId(),
                        String.format("%s %s", user.getProfile().getFirstName(), user.getProfile().getLastName()),
                        user.getProfile().getEmail()
                ))
                .collect(Collectors.toList());

        return new ObjectDataResponse(
                typeBuilder.from(users)
        );
    }
}
