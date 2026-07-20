/*
 * The MIT License
 *
 * Copyright 2025 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.github_branch_source;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.Serializable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;

/**
 * Represents the result of a passthrough authentication request.
 * Contains the token and additional metadata like scopes, permissions, and group information.
 * Implements Serializable to support Jenkins remoting (master-to-agent credential transfer).
 */
public class PassthroughAuthResult implements Serializable {
    
    private static final long serialVersionUID = 1L;

    /** Sentinel value used when the passthrough service does not report a token expiry. */
    public static final long EXPIRY_UNKNOWN = 0L;

    /**
     * Refresh the token this many milliseconds before its reported expiry, so it is replaced
     * before GitHub starts rejecting it with "Bad credentials". Non-final for testing.
     */
    static long REFRESH_MARGIN_MILLIS = Long.getLong(
            PassthroughAuthResult.class.getName() + ".REFRESH_MARGIN_MILLIS",
            Duration.ofMinutes(5).toMillis());

    /**
     * When the passthrough service does not report an expiry, treat the token as stale this many
     * milliseconds after it was acquired. GitHub App installation tokens live one hour, so this
     * stays comfortably below that. Non-final for testing.
     */
    static long FALLBACK_LIFETIME_MILLIS = Long.getLong(
            PassthroughAuthResult.class.getName() + ".FALLBACK_LIFETIME_MILLIS",
            Duration.ofMinutes(45).toMillis());

    private final String token;
    private final List<String> scopes;
    private final String permissions;
    private final List<String> userGroups;
    private final List<String> matchingTeams;
    private final long acquiredAtEpochMilli;
    private final long expiresAtEpochMilli;

    public PassthroughAuthResult(@NonNull String token,
                                List<String> scopes,
                                String permissions,
                                List<String> userGroups,
                                List<String> matchingTeams) {
        this(token, scopes, permissions, userGroups, matchingTeams, EXPIRY_UNKNOWN);
    }

    public PassthroughAuthResult(@NonNull String token,
                                List<String> scopes,
                                String permissions,
                                List<String> userGroups,
                                List<String> matchingTeams,
                                long expiresAtEpochMilli) {
        this.token = token;
        this.scopes = scopes != null ? Collections.unmodifiableList(new ArrayList<>(scopes)) : Collections.emptyList();
        this.permissions = permissions;
        this.userGroups = userGroups != null ? Collections.unmodifiableList(new ArrayList<>(userGroups)) : Collections.emptyList();
        this.matchingTeams = matchingTeams != null ? Collections.unmodifiableList(new ArrayList<>(matchingTeams)) : Collections.emptyList();
        this.expiresAtEpochMilli = expiresAtEpochMilli;
        this.acquiredAtEpochMilli = System.currentTimeMillis();
    }
    
    @NonNull
    public String getToken() {
        return token;
    }
    
    @NonNull
    public List<String> getScopes() {
        return scopes;
    }
    
    public String getPermissions() {
        return permissions;
    }
    
    @NonNull
    public List<String> getUserGroups() {
        return userGroups;
    }
    
    @NonNull
    public List<String> getMatchingTeams() {
        return matchingTeams;
    }

    /**
     * The instant, in epoch milliseconds, at which the underlying token expires, or
     * {@link #EXPIRY_UNKNOWN} if the passthrough service did not report an expiry.
     *
     * @return the token expiry in epoch milliseconds, or {@link #EXPIRY_UNKNOWN}
     */
    public long getExpiresAtEpochMilli() {
        return expiresAtEpochMilli;
    }

    /**
     * Whether the cached token should be refreshed before it is used again.
     *
     * <p>When the passthrough service reported an expiry, the token is considered stale once it is
     * within {@link #REFRESH_MARGIN_MILLIS} of that expiry. Otherwise it is considered stale once
     * {@link #FALLBACK_LIFETIME_MILLIS} has elapsed since it was acquired. This prevents long-idle
     * pipelines from reusing an expired GitHub App installation token and failing with a 401 "Bad
     * credentials" error.
     *
     * @return {@code true} if the token should be re-acquired, otherwise {@code false}
     */
    public boolean isStale() {
        long now = System.currentTimeMillis();
        if (expiresAtEpochMilli > EXPIRY_UNKNOWN) {
            return now >= expiresAtEpochMilli - REFRESH_MARGIN_MILLIS;
        }
        return now >= acquiredAtEpochMilli + FALLBACK_LIFETIME_MILLIS;
    }
    
    /**
     * Creates a formatted string for display in validation messages.
     * 
     * @return a formatted string containing scopes and permissions information
     */
    public String getDisplayInfo() {
        StringBuilder sb = new StringBuilder();
        
        if (!scopes.isEmpty()) {
            sb.append("Scopes: [").append(String.join(", ", scopes)).append("]");
        }
        
        if (permissions != null && !permissions.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("Permissions: ").append(permissions);
        }
        
        if (!userGroups.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("User Groups: [").append(String.join(", ", userGroups)).append("]");
        }
        
        if (!matchingTeams.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("Matching Teams: [").append(String.join(", ", matchingTeams)).append("]");
        }
        
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return "PassthroughAuthResult{" +
               "scopes=" + scopes +
               ", permissions='" + permissions + '\'' +
               ", userGroups=" + userGroups +
               ", matchingTeams=" + matchingTeams +
               '}';
    }
}