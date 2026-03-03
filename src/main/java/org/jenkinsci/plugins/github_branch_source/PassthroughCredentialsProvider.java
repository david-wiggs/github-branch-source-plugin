package org.jenkinsci.plugins.github_branch_source;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.security.core.Authentication;

/**
 * Runtime-only credentials provider used to expose passthrough token credentials to native Git checkout.
 */
@Extension
@Restricted(NoExternalUse.class)
public class PassthroughCredentialsProvider extends CredentialsProvider {

    private static final long CREDENTIAL_TTL_MILLIS = TimeUnit.MINUTES.toMillis(10);
    private static final Map<String, RegisteredCredential> REGISTERED = new ConcurrentHashMap<>();

    private static final class RegisteredCredential {
        private final PassthroughTokenCredentials credentials;
        private final long expiresAt;

        private RegisteredCredential(PassthroughTokenCredentials credentials, long expiresAt) {
            this.credentials = credentials;
            this.expiresAt = expiresAt;
        }
    }

    static void register(@NonNull PassthroughTokenCredentials credentials) {
        long expiresAt = System.currentTimeMillis() + CREDENTIAL_TTL_MILLIS;
        REGISTERED.put(credentials.getId(), new RegisteredCredential(credentials, expiresAt));
        cleanupExpiredEntries();
    }

    @Override
    public String getDisplayName() {
        return "GitHub Branch Source Passthrough Credentials";
    }

    @Override
    public <C extends Credentials> List<C> getCredentialsInItem(
            @NonNull Class<C> type,
            Item item,
            Authentication authentication,
            List<DomainRequirement> domainRequirements) {
        return currentCredentials(type);
    }

    @Override
    public <C extends Credentials> List<C> getCredentialsInItemGroup(
            @NonNull Class<C> type,
            ItemGroup itemGroup,
            Authentication authentication,
            List<DomainRequirement> domainRequirements) {
        return currentCredentials(type);
    }

    @SuppressWarnings("unchecked")
    private static <C extends Credentials> List<C> currentCredentials(@NonNull Class<C> type) {
        cleanupExpiredEntries();
        List<C> result = new java.util.ArrayList<>();
        for (RegisteredCredential entry : REGISTERED.values()) {
            if (type.isInstance(entry.credentials)) {
                result.add((C) entry.credentials);
            }
        }
        return Collections.unmodifiableList(result);
    }

    private static void cleanupExpiredEntries() {
        long now = System.currentTimeMillis();
        REGISTERED.entrySet().removeIf(entry -> entry.getValue().expiresAt <= now);
    }
}
