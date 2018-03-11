package com.boomi.flow.services.okta.applications;

import com.manywho.sdk.api.ContentType;
import com.manywho.sdk.services.actions.Action;

@Action.Metadata(name = "Get Application Username", summary = "Get a user's username for a specific application", uri = "applications/get-username")
public class GetApplicationUsername implements Action {
    public static class Input {
        @Action.Input(name = "Application ID", contentType = ContentType.String)
        private String application;

        @Action.Input(name = "User ID", contentType = ContentType.String, required = false)
        private String user;

        public String getApplication() {
            return application;
        }

        public String getUser() {
            return user;
        }
    }

    public static class Output {
        @Action.Output(name = "Username", contentType = ContentType.String)
        private String username;

        public Output(String username) {
            this.username = username;
        }

        public String getUsername() {
            return username;
        }
    }
}
