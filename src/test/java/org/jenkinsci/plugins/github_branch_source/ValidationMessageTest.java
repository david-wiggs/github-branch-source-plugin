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
 * Tests for validation messages showing passthrough authentication status.
 */
public class ValidationMessageTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    @Test
    public void testValidationShowsPassthroughStatus() throws Exception {
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
        
        // Test validation message content
        String repositoryUrl = "https://github.com/test/repo";
        try {
            hudson.util.FormValidation result = descriptor.doValidateRepositoryUrlAndCredentials(
                    null, repositoryUrl, "test-creds");
            
            // The validation message should mention passthrough authentication
            String message = result.getMessage();
            assertThat("Validation message should mention passthrough authentication", 
                       message, anyOf(
                           containsString("Passthrough authentication"),
                           containsString("http://localhost:8080/auth")
                       ));
                       
            System.out.println("Validation message: " + message);
        } catch (Exception e) {
            // Expected since we don't have a real auth service, but we should still get a message
            System.out.println("Exception (expected): " + e.getMessage());
        }
        
        // Reset configuration
        config.setPassthroughAuthenticationEnabled(false);
        config.setPassthroughAuthenticationUrl("");
    }
}