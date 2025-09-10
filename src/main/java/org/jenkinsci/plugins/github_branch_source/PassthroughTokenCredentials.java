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
 */
public class PassthroughTokenCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {
    
    private static final long serialVersionUID = 1L;
    
    private final String username;
    private final Secret token;
    
    public PassthroughTokenCredentials(@NonNull CredentialsScope scope,
                                     @NonNull String id, 
                                     @NonNull String description,
                                     @NonNull String username, 
                                     @NonNull String token) {
        super(scope, id, description);
        this.username = username;
        this.token = Secret.fromString(token);
    }
    
    @NonNull
    @Override
    public String getUsername() {
        return username;
    }
    
    @NonNull
    @Override
    public Secret getPassword() {
        return token;
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
        return "PassthroughTokenCredentials[" + getId() + "/" + getUsername() + "]";
    }
}
