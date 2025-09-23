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
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.model.TaskListener;
import hudson.util.StreamTaskListener;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

/**
 * Test to verify no fallback behavior when passthrough authentication is enabled.
 */
public class NoFallbackTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();
    
    @Rule
    public WireMockRule wireMockRule = new WireMockRule(9998);

    @Test
    public void testNoFallbackWhenPassthroughEnabled() throws Exception {
        // Set up a mock external authentication service that returns 401
        wireMockRule.stubFor(post(urlEqualTo("/auth"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"error\":\"Invalid credentials\",\"message\":\"Authentication failed\"}")));

        // Configure passthrough authentication
        GitHubConfiguration config = GitHubConfiguration.get();
        config.setPassthroughAuthenticationEnabled(true);
        config.setPassthroughAuthenticationUrl("http://localhost:9998/auth");
        config.save();

        // Create a task listener to capture output
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        TaskListener listener = new StreamTaskListener(new PrintStream(outputStream));

        // Create mock credentials
        MockStandardUsernamePasswordCredentials mockCreds = new MockStandardUsernamePasswordCredentials(
            "testuser", "testpass");

        // Test that lookupScanCredentialsWithPassthrough throws exception instead of falling back
        try {
            Connector.lookupScanCredentialsWithPassthrough(
                null, // context
                "https://api.github.com", // apiUri
                "test-creds", // scanCredentialsId
                "owner", // repoOwner
                "https://github.com/owner/repo", // repositoryUrl
                listener
            );
            fail("Expected RuntimeException when passthrough authentication fails");
        } catch (RuntimeException e) {
            // This is expected - passthrough authentication should fail and throw exception
            assertThat("Exception should mention passthrough authentication failure", 
                e.getMessage(), containsString("Passthrough authentication failed"));
            
            String output = outputStream.toString();
            assertThat("Output should show authentication failure", 
                output, containsString("authentication failed"));
        }
        
        // Verify the request was made correctly
        wireMockRule.verify(postRequestedFor(urlEqualTo("/auth"))
            .withHeader("Content-Type", equalTo("application/json")));
    }

    @Test
    public void testFallbackWhenPassthroughDisabled() throws Exception {
        // Disable passthrough authentication
        GitHubConfiguration config = GitHubConfiguration.get();
        config.setPassthroughAuthenticationEnabled(false);
        config.save();

        // Create a task listener
        TaskListener listener = TaskListener.NULL;

        // Test that lookupScanCredentialsWithPassthrough falls back to normal credentials when disabled
        // Since we don't have actual credentials set up, this should return null (normal behavior)
        try {
            Object result = Connector.lookupScanCredentialsWithPassthrough(
                null, // context
                "https://api.github.com", // apiUri
                "test-creds", // scanCredentialsId
                "owner", // repoOwner
                "https://github.com/owner/repo", // repositoryUrl
                listener
            );
            // Should not throw exception when passthrough is disabled
            // Result might be null due to no actual credentials configured, which is fine
        } catch (RuntimeException e) {
            fail("Should not throw exception when passthrough authentication is disabled");
        }
        
        // Verify no request was made to the auth service
        wireMockRule.verify(0, postRequestedFor(urlEqualTo("/auth")));
    }

    // Mock credentials class for testing
    private static class MockStandardUsernamePasswordCredentials 
            implements com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials {
        
        private final String username;
        private final String password;
        
        public MockStandardUsernamePasswordCredentials(String username, String password) {
            this.username = username;
            this.password = password;
        }
        
        @Override
        public String getUsername() { return username; }
        
        @Override
        public hudson.util.Secret getPassword() { 
            return hudson.util.Secret.fromString(password); 
        }
        
        @Override
        public com.cloudbees.plugins.credentials.CredentialsScope getScope() { 
            return com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL; 
        }
        
        @Override
        public String getId() { return "test-creds"; }
        
        @Override
        public String getDescription() { return "Test credentials"; }
        
        @Override
        public com.cloudbees.plugins.credentials.CredentialsDescriptor getDescriptor() {
            return null; // Not needed for this test
        }
    }
}