package org.jenkinsci.plugins.github_branch_source;

import static org.jenkinsci.plugins.github_branch_source.GitHubSCMNavigator.DescriptorImpl.getPossibleApiUriItems;

import com.cloudbees.jenkins.GitHubRepositoryName;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.coravy.hudson.plugins.github.GithubProjectProperty;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Functions;
import hudson.Util;
import hudson.model.Job;
import hudson.model.Run;
import hudson.remoting.Channel;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.scm.api.SCMSource;
import jenkins.security.SlaveToMasterCallable;
import jenkins.util.JenkinsJVM;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.workflow.support.concurrent.Timeout;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.github.GHApp;
import org.kohsuke.github.GHAppInstallation;
import org.kohsuke.github.GHAppInstallationToken;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.authorization.AuthorizationProvider;
import org.kohsuke.github.extras.authorization.JWTTokenProvider;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * A {@link Credentials} for GitHub Apps installed at the Enterprise Server level.
 * <p>
 * This class extends the functionality of {@link GitHubAppCredentials} to support 
 * GitHub Enterprise Server installations where the GitHub App is installed at the 
 * server level rather than at the organization level.
 * <p>
 * Unlike organization-level GitHub Apps that use the {@code owner} field to specify 
 * which organization/user the app is installed for, Enterprise-level GitHub Apps 
 * are installed at the server level and can access all organizations on that server 
 * (subject to the app's permissions).
 * 
 * @since 2.15.0
 */
@SuppressFBWarnings(value = "SE_NO_SERIALVERSIONID", justification = "XStream")
public class GitHubEnterpriseAppCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {

    private static final Logger LOGGER = Logger.getLogger(GitHubEnterpriseAppCredentials.class.getName());

    private static final String ERROR_AUTHENTICATING_GITHUB_APP = "Couldn't authenticate with GitHub Enterprise app ID %s";
    private static final String NOT_INSTALLED = ", has it been installed to your GitHub Enterprise server?";

    private static final String ERROR_NOT_INSTALLED = ERROR_AUTHENTICATING_GITHUB_APP + NOT_INSTALLED;
    private static final String ERROR_NO_INSTALLATION_FOUND =
            "No installations found for GitHub Enterprise app ID %s on server %s. "
                    + "Ensure the app is installed at the Enterprise level.";

    /**
     * When a new {@link AppInstallationToken} is generated, wait this many seconds before continuing.
     * Has no effect when a cached token is used, only when a new token is generated.
     *
     * <p>It is unlikely that a GitHub Enterprise app installation token would be required immediately after being generated.
     * However, tests and other high frequency operations could be affected by this.
     *
     * <p>Setting the environment variable "JENKINS_GITHUB_ENTERPRISE_APP_TOKEN_GENERATION_DELAY" to a value between 0 and 60
     * can customize this value. A value outside this range is ignored and the default is used instead.
     */
    private static final int AFTER_TOKEN_GENERATION_DELAY_SECONDS;

    static {
        int value = 1;
        try {
            String delay = System.getenv("JENKINS_GITHUB_ENTERPRISE_APP_TOKEN_GENERATION_DELAY");
            if (delay != null) {
                int parsedValue = Integer.parseInt(delay);
                if (parsedValue >= 0 && parsedValue <= 60) {
                    value = parsedValue;
                }
            }
        } catch (NumberFormatException e) {
            // ignore
        }
        AFTER_TOKEN_GENERATION_DELAY_SECONDS = value;
    }

    @NonNull
    private final String appID;

    @NonNull
    private final Secret privateKey;

    private String apiUri;

    private transient AppInstallationToken cachedToken;

    /**
     * Cache of credentials specialized by {@link #getApiUri()}, so that {@link #cachedToken} is preserved.
     */
    private transient Map<String, GitHubEnterpriseAppCredentials> byApiUri;

    @DataBoundConstructor
    @SuppressWarnings("unused") // by stapler
    public GitHubEnterpriseAppCredentials(
            CredentialsScope scope,
            String id,
            @CheckForNull String description,
            @NonNull String appID,
            @NonNull Secret privateKey) {
        super(scope, id, description);
        this.appID = appID;
        this.privateKey = privateKey;
    }

    public String getApiUri() {
        return apiUri;
    }

    @DataBoundSetter
    public void setApiUri(String apiUri) {
        this.apiUri = apiUri;
    }

    @NonNull
    public String getAppID() {
        return appID;
    }

    @NonNull
    public Secret getPrivateKey() {
        return privateKey;
    }

    @SuppressWarnings("deprecation")
    AuthorizationProvider getAuthorizationProvider() {
        return new CredentialsTokenProvider(this);
    }

    private static AuthorizationProvider createJwtProvider(String appId, String appPrivateKey) {
        try {
            return new JWTTokenProvider(appId, appPrivateKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "Couldn't parse private key for GitHub Enterprise app, make sure it's PKCS#8 format", e);
        }
    }

    private abstract static class TokenProvider extends GitHub.DependentAuthorizationProvider {

        protected TokenProvider(String appID, String privateKey) {
            super(createJwtProvider(appID, privateKey));
        }

        /**
         * Create and return the specialized GitHub instance to be used for refreshing
         * AppInstallationToken
         *
         * <p>The {@link GitHub.DependentAuthorizationProvider} provides a specialized GitHub instance
         * that uses JWT for authorization and does not check rate limit since it doesn't apply for the
         * App endpoints when using JWT.
         */
        static GitHub createTokenRefreshGitHub(String appId, String appPrivateKey, String apiUrl) throws IOException {
            TokenProvider provider = new TokenProvider(appId, appPrivateKey) {
                @Override
                public String getEncodedAuthorization() throws IOException {
                    // Will never be called
                    return null;
                }
            };
            return Connector.createGitHubBuilder(apiUrl)
                    .withAuthorizationProvider(provider)
                    .build();
        }
    }

    private static class CredentialsTokenProvider extends TokenProvider {
        private final GitHubEnterpriseAppCredentials credentials;

        CredentialsTokenProvider(GitHubEnterpriseAppCredentials credentials) {
            super(credentials.getAppID(), credentials.getPrivateKey().getPlainText());
            this.credentials = credentials;
        }

        public String getEncodedAuthorization() throws IOException {
            Secret token = credentials.getToken(gitHub()).getToken();
            return String.format("token %s", token.getPlainText());
        }
    }

    @SuppressWarnings("deprecation") // preview features are required for GitHub app integration, GitHub api adds
    // deprecated to all preview methods
    static AppInstallationToken generateAppInstallationToken(
            GitHub gitHubApp, String appId, String appPrivateKey, String apiUrl) {
        JenkinsJVM.checkJenkinsJVM();
        // We expect this to be fast but if anything hangs in here we do not want to block indefinitely

        try (Timeout ignored = Timeout.limit(30, TimeUnit.SECONDS)) {
            if (gitHubApp == null) {
                gitHubApp = TokenProvider.createTokenRefreshGitHub(appId, appPrivateKey, apiUrl);
            }

            GHApp app;
            try {
                app = gitHubApp.getApp();
            } catch (IOException e) {
                throw new IllegalArgumentException(String.format(ERROR_AUTHENTICATING_GITHUB_APP, appId), e);
            }

            List<GHAppInstallation> appInstallations = app.listInstallations().asList();
            if (appInstallations.isEmpty()) {
                throw new IllegalArgumentException(String.format(ERROR_NOT_INSTALLED, appId));
            }
            
            // For GitHub Enterprise Apps, we expect to find a server-level installation
            // Look for an installation that matches the server (no specific account)
            GHAppInstallation appInstallation = null;
            
            // For Enterprise installations, there should typically be one installation at the server level
            // If there are multiple installations, prefer the one with the highest ID (most recent)
            appInstallation = appInstallations.stream()
                    .reduce((first, second) -> second) // Get the last (highest ID) installation
                    .orElse(null);
            
            if (appInstallation == null) {
                throw new IllegalArgumentException(
                        String.format(ERROR_NO_INSTALLATION_FOUND, appId, apiUrl));
            }

            GHAppInstallationToken appInstallationToken = appInstallation
                    .createToken(appInstallation.getPermissions())
                    .create();

            long expiration = getExpirationSeconds(appInstallationToken);
            AppInstallationToken token =
                    new AppInstallationToken(Secret.fromString(appInstallationToken.getToken()), expiration);
            LOGGER.log(Level.FINER, "Generated GitHub Enterprise App Installation Token for app ID {0}", appId);
            LOGGER.log(
                    Level.FINEST,
                    () -> "Generated GitHub Enterprise App Installation Token at " + Instant.now().toEpochMilli());

            if (AFTER_TOKEN_GENERATION_DELAY_SECONDS > 0) {
                // Delay can be up to 10 seconds.
                long tokenDelay = Math.min(10, AFTER_TOKEN_GENERATION_DELAY_SECONDS);
                LOGGER.log(Level.FINER, "Waiting {0} seconds after token generation", tokenDelay);
                Thread.sleep(Duration.ofSeconds(tokenDelay).toMillis());
            }

            return token;
        } catch (IOException | InterruptedException e) {
            throw new IllegalArgumentException(
                    "Failed to generate GitHub Enterprise app installation token for app ID " + appId, e);
        }
    }

    private static long getExpirationSeconds(GHAppInstallationToken appInstallationToken) {
        try {
            return appInstallationToken.getExpiresAt().toInstant().getEpochSecond();
        } catch (Exception e) {
            // if we fail to calculate the expiration, guess at a reasonable value.
            LOGGER.log(Level.WARNING, "Unable to get GitHub Enterprise app installation token expiration", e);
            return Instant.now().getEpochSecond() + AppInstallationToken.NOT_STALE_MINIMUM_SECONDS;
        }
    }

    @NonNull
    String actualApiUri() {
        return Util.fixEmpty(getApiUri()) == null ? "https://api.github.com" : getApiUri();
    }

    private AppInstallationToken getToken(GitHub gitHub) {
        synchronized (this) {
            try {
                if (cachedToken == null || cachedToken.isStale()) {
                    LOGGER.log(Level.FINE, "Generating GitHub Enterprise App Installation Token for app ID {0}", getAppID());
                    cachedToken = generateAppInstallationToken(
                            gitHub, getAppID(), getPrivateKey().getPlainText(), actualApiUri());
                    LOGGER.log(Level.FINER, "Retrieved GitHub Enterprise App Installation Token for app ID {0}", getAppID());
                }
            } catch (Exception e) {
                if (cachedToken != null && !cachedToken.isExpired()) {
                    // Requesting a new token failed. If the cached token is not expired, continue to use it.
                    // This minimizes failures due to occasional network instability,
                    // while only slightly increasing the chance that tokens will expire while in use.
                    LOGGER.log(
                            Level.WARNING,
                            "Failed to update stale GitHub Enterprise app installation token for app ID "
                                    + getAppID()
                                    + ", using cached token",
                            e);
                } else {
                    throw new RuntimeException(e);
                }
            }
            return cachedToken;
        }
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public Secret getPassword() {
        return this.getToken(null).getToken();
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public String getUsername() {
        return getAppID();
    }

    @Override
    public boolean isUsernameSecret() {
        return false;
    }

    @NonNull
    public synchronized GitHubEnterpriseAppCredentials withApiUri(@NonNull String apiUri) {
        if (this.getApiUri() != null) {
            if (!apiUri.equals(this.getApiUri())) {
                throw new IllegalArgumentException("API URI mismatch: " + this.getApiUri() + " vs. " + apiUri);
            }
            return this;
        }
        if (byApiUri == null) {
            byApiUri = new HashMap<>();
        }
        return byApiUri.computeIfAbsent(apiUri, k -> {
            GitHubEnterpriseAppCredentials clone =
                    new GitHubEnterpriseAppCredentials(getScope(), getId(), getDescription(), getAppID(), getPrivateKey());
            clone.apiUri = apiUri;
            return clone;
        });
    }

    @NonNull
    @Override
    public Credentials forRun(Run<?, ?> context) {
        Job<?, ?> job = context.getParent();
        SCMSource src = SCMSource.SourceByItem.findSource(job);
        if (src instanceof GitHubSCMSource) {
            GitHubSCMSource ghSrc = (GitHubSCMSource) src;
            return withApiUri(ghSrc.getApiUri());
        }
        GitHubRepositoryName ghrn = GitHubRepositoryName.create(job.getProperty(GithubProjectProperty.class));
        if (ghrn != null) {
            // For GitHub Enterprise apps, we use the API URI from the configuration
            return withApiUri(actualApiUri());
        }
        return this;
    }

    private AppInstallationToken getCachedToken() {
        synchronized (this) {
            return cachedToken;
        }
    }

    static class AppInstallationToken implements Serializable {

        private static final long serialVersionUID = 1L;

        /**
         * The minimum number of seconds before expiration to request a new token.
         *
         * <p>Ensures that tokens do not expire in the middle of a git checkout due to time we spend making GitHub API
         * calls.
         */
        static final long NOT_STALE_MINIMUM_SECONDS = Duration.ofMinutes(5).getSeconds();

        private final Secret token;
        private final long expirationEpochSeconds;
        private final long staleEpochSeconds;

        public AppInstallationToken(Secret token, long expirationEpochSeconds) {
            this.token = token;
            this.expirationEpochSeconds = expirationEpochSeconds;

            long now = Instant.now().getEpochSecond();
            long secondsUntilExpiration = expirationEpochSeconds - now;

            // We want to refresh the token before it expires,
            // but we also need to make sure we don't refresh it too often.
            long maximumAllowedAge = Math.max(NOT_STALE_MINIMUM_SECONDS * 2, secondsUntilExpiration / 2);
            long secondsUntilStale = secondsUntilExpiration - NOT_STALE_MINIMUM_SECONDS;
            if (secondsUntilStale > maximumAllowedAge) {
                secondsUntilStale = maximumAllowedAge;
            }

            LOGGER.log(Level.FINER, "Token will become stale after " + secondsUntilStale + " seconds");

            this.staleEpochSeconds = now + secondsUntilStale;
        }

        public Secret getToken() {
            return token;
        }

        public boolean isStale() {
            return Instant.now().getEpochSecond() >= staleEpochSeconds;
        }

        public boolean isExpired() {
            return Instant.now().getEpochSecond() >= expirationEpochSeconds;
        }

        long getTokenStaleEpochSeconds() {
            return staleEpochSeconds;
        }
    }

    /**
     * Ensures that the credentials state as serialized via Remoting to an agent calls back to the
     * controller. Benefits:
     *
     * <ul>
     *   <li>The token is cached locally and used until it is stale.
     *   <li>The agent never needs to have access to the plaintext private key.
     *   <li>We avoid the considerable amount of class loading associated with the JWT library,
     *       Jackson data binding, Bouncy Castle, etc.
     *   <li>The agent need not be able to contact GitHub.
     * </ul>
     */
    protected Object writeReplace() {
        if (
        /* XStream */ Channel.current() == null) {
            return this;
        }
        return new DelegatingGitHubEnterpriseAppCredentials(this);
    }

    private static final class DelegatingGitHubEnterpriseAppCredentials extends BaseStandardCredentials
            implements StandardUsernamePasswordCredentials {

        private final String appID;
        /**
         * An encrypted form of all data needed to refresh the token. Used to prevent {@link GetToken}
         * from being abused by compromised build agents.
         */
        private final String tokenRefreshData;

        private AppInstallationToken cachedToken;

        private transient Channel ch;

        DelegatingGitHubEnterpriseAppCredentials(GitHubEnterpriseAppCredentials onMaster) {
            super(onMaster.getScope(), onMaster.getId(), onMaster.getDescription());
            JenkinsJVM.checkJenkinsJVM();
            appID = onMaster.getAppID();
            JSONObject j = new JSONObject();
            j.put("appID", appID);
            j.put("privateKey", onMaster.getPrivateKey().getPlainText());
            j.put("apiUri", onMaster.actualApiUri());
            tokenRefreshData = Secret.fromString(j.toString()).getEncryptedValue();

            // Check token is valid before sending it to the agent.
            // Ensuring the cached token is not stale before sending it to agents keeps agents from having
            // to immediately refresh the token.
            // This is intentionally only a best-effort attempt.
            // If this fails, the agent will fallback to making the request (which may or may not fail).
            try {
                LOGGER.log(
                        Level.FINEST,
                        "Checking GitHub Enterprise App Installation Token for app ID {0} before sending to agent",
                        onMaster.getAppID());
                onMaster.getPassword();
            } catch (Exception e) {
                LOGGER.log(
                        Level.WARNING,
                        "Failed to update stale GitHub Enterprise app installation token for app ID "
                                + onMaster.getAppID()
                                + " before sending to agent",
                        e);
            }

            cachedToken = onMaster.getCachedToken();
        }

        private Object readResolve() {
            JenkinsJVM.checkNotJenkinsJVM();
            synchronized (this) {
                ch = Channel.currentOrFail();
            }
            return this;
        }

        @NonNull
        @Override
        public String getUsername() {
            return appID;
        }

        @Override
        public Secret getPassword() {
            JenkinsJVM.checkNotJenkinsJVM();
            try {
                synchronized (this) {
                    try {
                        if (cachedToken == null || cachedToken.isStale()) {
                            LOGGER.log(Level.FINE, "Generating GitHub Enterprise App Installation Token for app ID {0} on agent", appID);
                            cachedToken = ch.call(new GetToken(tokenRefreshData));
                            LOGGER.log(
                                    Level.FINER,
                                    "Retrieved GitHub Enterprise App Installation Token for app ID {0} on agent",
                                    appID);
                            LOGGER.log(
                                    Level.FINEST,
                                    () -> "Generated GitHub Enterprise App Installation Token at "
                                            + Instant.now().toEpochMilli()
                                            + " on agent");
                        }
                    } catch (Exception e) {
                        if (cachedToken != null && !cachedToken.isExpired()) {
                            // Requesting a new token failed. If the cached token is not expired, continue to use
                            // it.
                            // This minimizes failures due to occasional network instability,
                            // while only slightly increasing the chance that tokens will expire while in use.
                            LOGGER.log(
                                    Level.WARNING,
                                    "Failed to generate new GitHub Enterprise App Installation Token for app ID "
                                            + appID
                                            + " on agent, using cached token",
                                    e);
                        } else {
                            throw new RuntimeException(e);
                        }
                    }
                    return cachedToken.getToken();
                }
            } catch (RuntimeException x) {
                throw x;
            } catch (Exception x) {
                throw new RuntimeException(x);
            }
        }

        private static final class GetToken extends SlaveToMasterCallable<AppInstallationToken, RuntimeException> {

            private final String data;

            GetToken(String data) {
                this.data = data;
            }

            @Override
            public AppInstallationToken call() throws RuntimeException {
                JenkinsJVM.checkJenkinsJVM();
                JSONObject fields =
                        JSONObject.fromObject(Secret.fromString(data).getPlainText());
                LOGGER.log(
                        Level.FINE, "Generating GitHub Enterprise App Installation Token for app ID {0} for agent", fields.get("appID"));
                AppInstallationToken token = generateAppInstallationToken(
                        null,
                        (String) fields.get("appID"),
                        (String) fields.get("privateKey"),
                        (String) fields.get("apiUri"));
                LOGGER.log(
                        Level.FINER,
                        "Retrieved GitHub Enterprise App Installation Token for app ID {0} for agent",
                        fields.get("appID"));
                return token;
            }
        }
    }

    /** {@inheritDoc} */
    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        /** {@inheritDoc} */
        @Override
        public String getDisplayName() {
            return Messages.GitHubEnterpriseAppCredentials_displayName();
        }

        /** {@inheritDoc} */
        @Override
        public String getIconClassName() {
            return "symbol-logo-github plugin-ionicons-api";
        }

        @SuppressWarnings("unused") // jelly
        public boolean isApiUriSelectable() {
            return !GitHubConfiguration.get().getEndpoints().isEmpty();
        }

        /**
         * Returns the available GitHub endpoint items.
         *
         * @return the available GitHub endpoint items.
         */
        @SuppressWarnings("unused") // stapler
        @Restricted(NoExternalUse.class) // stapler
        public ListBoxModel doFillApiUriItems() {
            return getPossibleApiUriItems();
        }

        public FormValidation doCheckAppID(@QueryParameter String appID) {
            if (!appID.isEmpty()) {
                try {
                    Integer.parseInt(appID);
                } catch (NumberFormatException x) {
                    return FormValidation.warning("An app ID is likely to be a number, distinct from the app name");
                }
            }
            return FormValidation.ok();
        }

        @POST
        @SuppressWarnings("unused") // stapler
        @Restricted(NoExternalUse.class) // stapler
        public FormValidation doTestConnection(
                @QueryParameter("appID") final String appID,
                @QueryParameter("privateKey") final String privateKey,
                @QueryParameter("apiUri") final String apiUri) {

            GitHubEnterpriseAppCredentials gitHubEnterpriseAppCredentials = new GitHubEnterpriseAppCredentials(
                    CredentialsScope.GLOBAL, "test-id-not-being-saved", null, appID, Secret.fromString(privateKey));
            gitHubEnterpriseAppCredentials.setApiUri(apiUri);

            try {
                GitHub connect = Connector.connect(apiUri, gitHubEnterpriseAppCredentials);
                try {
                    return FormValidation.ok("Success, Remaining rate limit: "
                            + connect.getRateLimit().getRemaining());
                } finally {
                    Connector.release(connect);
                }
            } catch (Exception e) {
                return FormValidation.error(e, String.format(ERROR_AUTHENTICATING_GITHUB_APP, appID));
            }
        }
    }
}
