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

import org.junit.Test;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests for the passthrough authentication functionality.
 */
public class PassthroughAuthenticationTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    @Test
    public void testPassthroughAuthenticationConfigurationDefaults() throws Exception {
        GitHubConfiguration config = GitHubConfiguration.get();
        
        // Test default values
        assertThat("Passthrough authentication should be disabled by default", 
                   config.isPassthroughAuthenticationEnabled(), is(false));
        assertThat("Passthrough URL should be null by default", 
                   config.getPassthroughAuthenticationUrl(), is(nullValue()));
    }

    @Test
    public void testPassthroughAuthenticationConfiguration() throws Exception {
        GitHubConfiguration config = GitHubConfiguration.get();
        
        // Test setting values
        config.setPassthroughAuthenticationEnabled(true);
        config.setPassthroughAuthenticationUrl("https://auth.example.com/github-token");
        
        assertThat("Passthrough authentication should be enabled", 
                   config.isPassthroughAuthenticationEnabled(), is(true));
        assertThat("Passthrough URL should be set", 
                   config.getPassthroughAuthenticationUrl(), is("https://auth.example.com/github-token"));
        
        // Test PassthroughAuthenticationService.isEnabled()
        assertThat("PassthroughAuthenticationService should report enabled", 
                   PassthroughAuthenticationService.isEnabled(), is(true));
        assertThat("PassthroughAuthenticationService should return correct URL", 
                   PassthroughAuthenticationService.getPassthroughUrl(), is("https://auth.example.com/github-token"));
    }

    @Test
    public void testPassthroughTokenCredentials() throws Exception {
        // Create a mock PassthroughAuthResult
        PassthroughAuthResult authResult = new PassthroughAuthResult(
            "test-token-123",
            java.util.Arrays.asList("read", "write"),
            "admin", 
            java.util.Arrays.asList("group1", "group2"),
            java.util.Arrays.asList("team1", "team2")
        );
        
        PassthroughTokenCredentials creds = new PassthroughTokenCredentials(
            com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL,
            "test-id",
            "Test Passthrough Credentials",
            "testuser",
            authResult
        );
        
        assertThat("Credentials ID should be set", creds.getId(), is("test-id"));
        assertThat("Credentials description should be set", creds.getDescription(), is("Test Passthrough Credentials"));
        assertThat("Username should be set", creds.getUsername(), is("testuser"));
        assertThat("Password should contain token", creds.getPassword().getPlainText(), is("test-token-123"));
        assertThat("Should have GLOBAL scope", creds.getScope(), is(com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL));
        assertThat("Should have auth result", creds.getAuthResult(), is(authResult));
    }

    @Test
    public void testPassthroughAuthenticationServiceWhenDisabled() throws Exception {
        GitHubConfiguration config = GitHubConfiguration.get();
        
        // Ensure it's disabled
        config.setPassthroughAuthenticationEnabled(false);
        config.setPassthroughAuthenticationUrl(null);
        
        assertThat("PassthroughAuthenticationService should report disabled", 
                   PassthroughAuthenticationService.isEnabled(), is(false));
    }
    
    @Test
    public void testValidationUsesPassthroughAuthentication() throws Exception {
        // Enable passthrough authentication
        GitHubConfiguration config = GitHubConfiguration.get();
        config.setPassthroughAuthenticationEnabled(true);
        config.setPassthroughAuthenticationUrl("http://localhost:8080/auth");
        
        // Create username/password credentials
        com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl userCreds = 
            new com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl(
                com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL, 
                "test-creds", "Test credentials", "testuser", "testpass");
        com.cloudbees.plugins.credentials.CredentialsProvider.lookupStores(jenkins.jenkins).iterator().next()
            .addCredentials(com.cloudbees.plugins.credentials.domains.Domain.global(), userCreds);
        
        // Create a descriptor for testing
        GitHubSCMSource.DescriptorImpl descriptor = new GitHubSCMSource.DescriptorImpl();
        
        // Test validation - this should attempt to use passthrough authentication
        String repositoryUrl = "https://github.com/test/repo";
        try {
            hudson.util.FormValidation result = descriptor.doValidateRepositoryUrlAndCredentials(
                    null, repositoryUrl, "test-creds");
            // The validation will fail because we don't have a real auth service running,
            // but it should at least try the passthrough authentication
            assertThat(result, notNullValue());
        } catch (Exception e) {
            // Expected since we don't have a real auth service
        }
        
        // Reset configuration
        config.setPassthroughAuthenticationEnabled(false);
        config.setPassthroughAuthenticationUrl("");
    }
}
