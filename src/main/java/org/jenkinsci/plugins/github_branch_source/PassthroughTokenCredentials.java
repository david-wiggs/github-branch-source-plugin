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

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;

/**
 * Credentials implementation that wraps a token obtained via passthrough authentication.
 * Uses "x-access-token" as the username, which is required by GitHub for
 * authenticating with GitHub App installation tokens over HTTPS.
 */
public class PassthroughTokenCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {
    
    private static final long serialVersionUID = 1L;
    
    private static final String GITHUB_TOKEN_USERNAME = "x-access-token";
    
    private final String originalUsername;
    private final Secret token;
    private final PassthroughAuthResult authResult;
    
    public PassthroughTokenCredentials(@NonNull CredentialsScope scope,
                                     @NonNull String id, 
                                     @NonNull String description,
                                     @NonNull String username, 
                                     @NonNull PassthroughAuthResult authResult) {
        super(scope, id, description);
        this.originalUsername = username;
        this.token = Secret.fromString(authResult.getToken());
        this.authResult = authResult;
    }
    
    @NonNull
    @Override
    public String getUsername() {
        return GITHUB_TOKEN_USERNAME;
    }
    
    /**
     * Gets the original username that was used to authenticate with the passthrough service.
     *
     * @return the original username
     */
    @NonNull
    public String getOriginalUsername() {
        return originalUsername;
    }
    
    @NonNull
    @Override
    public Secret getPassword() {
        return token;
    }
    
    /**
     * Gets the full authentication result including scopes, permissions, and group information.
     * 
     * @return the PassthroughAuthResult containing all authentication metadata
     */
    @NonNull
    public PassthroughAuthResult getAuthResult() {
        return authResult;
    }
    
    @NonNull
    @Override
    public CredentialsDescriptor getDescriptor() {
        // Return a simple descriptor for passthrough token credentials
        return new CredentialsDescriptor() {
            @Override
            public String getDisplayName() {
                return "Passthrough Token Credentials";
            }
        };
    }
    
    @Override
    public String toString() {
        return "PassthroughTokenCredentials[" + getId() + "/" + originalUsername + "]";
    }
}
