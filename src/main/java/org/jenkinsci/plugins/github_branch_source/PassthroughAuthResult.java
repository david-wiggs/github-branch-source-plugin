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
    
    private final String token;
    private final List<String> scopes;
    private final String permissions;
    private final List<String> userGroups;
    private final List<String> matchingTeams;
    
    public PassthroughAuthResult(@NonNull String token, 
                                List<String> scopes,
                                String permissions,
                                List<String> userGroups,
                                List<String> matchingTeams) {
        this.token = token;
        this.scopes = scopes != null ? Collections.unmodifiableList(new ArrayList<>(scopes)) : Collections.emptyList();
        this.permissions = permissions;
        this.userGroups = userGroups != null ? Collections.unmodifiableList(new ArrayList<>(userGroups)) : Collections.emptyList();
        this.matchingTeams = matchingTeams != null ? Collections.unmodifiableList(new ArrayList<>(matchingTeams)) : Collections.emptyList();
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