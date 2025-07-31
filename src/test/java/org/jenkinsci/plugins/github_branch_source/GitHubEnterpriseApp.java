package org.jenkinsci.plugins.github_branch_source;

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.Secret;

public class GitHubEnterpriseApp {
    
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9XYMKFZv8b9z1\n"
            + "9Eb9W8Y7qhQ9w8j9Fz8TzMx7tMjQV9lXnJ7Y8s9n8QZqYm8Qb7t6h3q8dVt9Q9\n"
            + "8T3K7n5yY6fQ9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7j\n"
            + "Vt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ\n"
            + "1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s\n"
            + "7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMv\n"
            + "FCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8\n"
            + "nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7\n"
            + "jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQK\n"
            + "J1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8\n"
            + "s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wM\n"
            + "vFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t\n"
            + "8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q\n"
            + "7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQ\n"
            + "KJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt\n"
            + "8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4w\n"
            + "MvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8\n"
            + "t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1\n"
            + "q7jVt9a6VjQKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6Vj\n"
            + "QKJ1F9jYjXt8s7k1t8J4wMvFCKVzZz8t8nYt8W8x1q7jVt9a6VjQKJ1F9jYjX\n"
            + "-----END PRIVATE KEY-----";

    public static GitHubEnterpriseAppCredentials createCredentials(final String id) {
        return new GitHubEnterpriseAppCredentials(CredentialsScope.GLOBAL, id, "sample", "54321", Secret.fromString(PRIVATE_KEY));
    }

    public static GitHubEnterpriseAppCredentials createCredentials(final String id, final String apiUri) {
        final var credentials = createCredentials(id);
        credentials.setApiUri(apiUri);
        return credentials;
    }
}
