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

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.TaskListener;
import net.sf.json.JSONObject;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Service for handling passthrough authentication with external authentication providers.
 */
public class PassthroughAuthenticationService {
    
    private static final Logger LOGGER = Logger.getLogger(PassthroughAuthenticationService.class.getName());
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Performs passthrough authentication by sending credentials to the configured URL
     * and expecting a token back.
     *
     * @param passthroughUrl the URL to send authentication request to
     * @param repositoryUrl the repository URL being accessed
     * @param credentials the username/password credentials
     * @param apiUri the GitHub API URI
     * @param repositoryOwner the repository owner
     * @param repositoryName the repository name
     * @param listener the task listener for logging
     * @return the authentication token or null if authentication failed
     * @throws IOException if there's an error during the request
     */
    @NonNull
    public static String authenticate(@NonNull String passthroughUrl,
                                    @NonNull String repositoryUrl,
                                    @NonNull StandardUsernamePasswordCredentials credentials,
                                    @NonNull String apiUri,
                                    @NonNull String repositoryOwner,
                                    @NonNull String repositoryName,
                                    @NonNull TaskListener listener) throws IOException {
        
        LOGGER.log(Level.FINE, "Attempting passthrough authentication for repository: {0}", repositoryUrl);
        
        // Create authentication request JSON
        JSONObject request = new JSONObject();
        request.put("repositoryUrl", repositoryUrl);
        request.put("username", credentials.getUsername());
        request.put("password", credentials.getPassword().getPlainText());
        request.put("apiUri", apiUri);
        request.put("repositoryOwner", repositoryOwner);
        request.put("repositoryName", repositoryName);
        
        String requestJson = request.toString();
        
        // Create HTTP client and request
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .build();
            
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(passthroughUrl))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(REQUEST_TIMEOUT)
            .POST(HttpRequest.BodyPublishers.ofString(requestJson))
            .build();
        
        // Send request
        HttpResponse<String> response;
        try {
            response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            String errorMsg = "Failed to send passthrough authentication request to " + passthroughUrl;
            LOGGER.log(Level.WARNING, errorMsg, e);
            listener.error(errorMsg + ": " + e.getMessage());
            throw new IOException(errorMsg, e);
        }
        
        // Check response status
        if (response.statusCode() != 200) {
            String errorMsg = "Passthrough authentication failed with status " + response.statusCode() + 
                            ": " + response.body();
            LOGGER.log(Level.WARNING, errorMsg);
            listener.error(errorMsg);
            throw new IOException(errorMsg);
        }
        
        // Parse response
        JSONObject authResponse;
        try {
            authResponse = JSONObject.fromObject(response.body());
        } catch (Exception e) {
            String errorMsg = "Failed to parse authentication response: " + response.body();
            LOGGER.log(Level.WARNING, errorMsg, e);
            listener.error(errorMsg);
            throw new IOException(errorMsg, e);
        }
        
        // Check if authentication was successful
        boolean success = authResponse.optBoolean("success", false);
        String token = authResponse.optString("token");
        String message = authResponse.optString("message");
        
        if (!success || token == null || token.trim().isEmpty()) {
            String errorMsg = "Passthrough authentication failed: " + 
                            (message != null && !message.isEmpty() ? message : "No token received");
            LOGGER.log(Level.WARNING, errorMsg);
            listener.error(errorMsg);
            throw new IOException(errorMsg);
        }
        
        LOGGER.log(Level.FINE, "Passthrough authentication successful for repository: {0}", repositoryUrl);
        listener.getLogger().println("Passthrough authentication successful");
        
        return token;
    }
    
    /**
     * Checks if passthrough authentication is enabled and configured.
     *
     * @return true if passthrough authentication is enabled and URL is configured
     */
    public static boolean isEnabled() {
        GitHubConfiguration config = GitHubConfiguration.get();
        return config.isPassthroughAuthenticationEnabled() && 
               config.getPassthroughAuthenticationUrl() != null;
    }
    
    /**
     * Gets the configured passthrough authentication URL.
     *
     * @return the passthrough authentication URL or null if not configured
     */
    public static String getPassthroughUrl() {
        GitHubConfiguration config = GitHubConfiguration.get();
        return config.getPassthroughAuthenticationUrl();
    }
}
