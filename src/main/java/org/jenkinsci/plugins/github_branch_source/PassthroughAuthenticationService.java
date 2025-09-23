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
     * Obfuscates sensitive data in JSON strings for safe logging.
     * Replaces password and token values with asterisks.
     * 
     * @param jsonString the JSON string to obfuscate
     * @return the obfuscated JSON string
     */
    private static String obfuscateJsonForLogging(String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return jsonString;
        }
        
        try {
            JSONObject json = JSONObject.fromObject(jsonString);
            JSONObject safeJson = new JSONObject();
            
            // Copy all fields, but obfuscate sensitive ones
            for (Object keyObj : json.keySet()) {
                String key = keyObj.toString();
                Object value = json.get(key);
                
                if ("password".equalsIgnoreCase(key) || "token".equalsIgnoreCase(key)) {
                    // Obfuscate sensitive fields
                    if (value != null && value.toString().length() > 0) {
                        safeJson.put(key, "***");
                    } else {
                        safeJson.put(key, value);
                    }
                } else {
                    // Keep non-sensitive fields as-is
                    safeJson.put(key, value);
                }
            }
            
            return safeJson.toString();
        } catch (Exception e) {
            // If JSON parsing fails, do basic string replacement for various formats
            String result = jsonString;
            
            // Handle JSON-style patterns: "password":"value"
            result = result.replaceAll("(\"password\"\\s*:\\s*\")([^\"]*)(\")", "$1***$3");
            result = result.replaceAll("(\"token\"\\s*:\\s*\")([^\"]*)(\")", "$1***$3");
            
            // Handle other patterns: password: value, password=value, etc.
            result = result.replaceAll("(password\\s*[:=]\\s*)([^,\\s}]+)", "$1***");
            result = result.replaceAll("(token\\s*[:=]\\s*)([^,\\s}]+)", "$1***");
            
            return result;
        }
    }

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
        request.put("username", credentials.getUsername());
        request.put("password", credentials.getPassword().getPlainText());
        request.put("repository", repositoryName);
        request.put("organization", repositoryOwner);
        
        String requestJson = request.toString();
        
        // Log the request for debugging (with sensitive data obfuscated)
        LOGGER.log(Level.INFO, "Sending passthrough authentication request to {0}: {1}", 
                   new Object[]{passthroughUrl, obfuscateJsonForLogging(requestJson)});
        
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
            LOGGER.log(Level.INFO, errorMsg + ": " + e.getMessage());
            listener.error(errorMsg + ": " + e.getMessage());
            throw new IOException(errorMsg, e);
        }
        
        // Log response details for debugging
        LOGGER.log(Level.INFO, "Passthrough authentication response status: {0}, Content-Type: {1}", 
                   new Object[]{response.statusCode(), response.headers().firstValue("Content-Type").orElse("unknown")});
        
        // Check response status
        if (response.statusCode() != 200) {
            String responseBody = response.body();
            String errorMsg = "Passthrough authentication failed with status " + response.statusCode() + 
                            ": " + obfuscateJsonForLogging(responseBody);
            LOGGER.log(Level.INFO, errorMsg);
            listener.error(errorMsg);
            throw new IOException(errorMsg);
        }
        
        // Parse response
        String responseBody = response.body();
        if (responseBody == null || responseBody.trim().isEmpty()) {
            String errorMsg = "Passthrough authentication failed: Empty response body from " + passthroughUrl;
            LOGGER.log(Level.INFO, errorMsg);
            listener.error(errorMsg);
            throw new IOException(errorMsg);
        }
        
        // Log the response for debugging (with sensitive data obfuscated)
        LOGGER.log(Level.INFO, "Passthrough authentication response from {0}: {1}", 
                   new Object[]{passthroughUrl, obfuscateJsonForLogging(responseBody)});
        
        JSONObject authResponse;
        try {
            authResponse = JSONObject.fromObject(responseBody.trim());
        } catch (Exception e) {
            String errorMsg = "Failed to parse authentication response as JSON. Response was: " + obfuscateJsonForLogging(responseBody);
            LOGGER.log(Level.INFO, errorMsg + ": " + e.getMessage());
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
            LOGGER.log(Level.INFO, errorMsg);
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
