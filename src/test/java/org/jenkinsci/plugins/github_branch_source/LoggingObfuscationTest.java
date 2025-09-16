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

import java.lang.reflect.Method;

/**
 * Tests for logging obfuscation functionality.
 */
public class LoggingObfuscationTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    @Test
    public void testObfuscateJsonForLogging() throws Exception {
        // Use reflection to access the private method
        Method obfuscateMethod = PassthroughAuthenticationService.class.getDeclaredMethod("obfuscateJsonForLogging", String.class);
        obfuscateMethod.setAccessible(true);
        
        // Test request JSON obfuscation
        String requestJson = "{\"username\":\"testuser\",\"password\":\"secretpass123\",\"repository\":\"testrepo\",\"organization\":\"testorg\"}";
        String obfuscatedRequest = (String) obfuscateMethod.invoke(null, requestJson);
        
        assertThat("Request should contain username", obfuscatedRequest, containsString("testuser"));
        assertThat("Request should contain repository", obfuscatedRequest, containsString("testrepo"));
        assertThat("Request should contain organization", obfuscatedRequest, containsString("testorg"));
        assertThat("Request should NOT contain actual password", obfuscatedRequest, not(containsString("secretpass123")));
        assertThat("Request should contain obfuscated password", obfuscatedRequest, containsString("***"));
        
        // Test response JSON obfuscation
        String responseJson = "{\"success\":true,\"token\":\"ghp_secrettoken123\",\"message\":\"Auth successful\"}";
        String obfuscatedResponse = (String) obfuscateMethod.invoke(null, responseJson);
        
        assertThat("Response should contain success", obfuscatedResponse, containsString("true"));
        assertThat("Response should contain message", obfuscatedResponse, containsString("Auth successful"));
        assertThat("Response should NOT contain actual token", obfuscatedResponse, not(containsString("ghp_secrettoken123")));
        assertThat("Response should contain obfuscated token", obfuscatedResponse, containsString("***"));
        
        // Test invalid JSON fallback
        String invalidJson = "username: testuser, password: secretpass123, token: ghp_secrettoken123";
        String obfuscatedInvalid = (String) obfuscateMethod.invoke(null, invalidJson);
        
        assertThat("Invalid JSON should still obfuscate passwords", obfuscatedInvalid, not(containsString("secretpass123")));
        assertThat("Invalid JSON should still obfuscate tokens", obfuscatedInvalid, not(containsString("ghp_secrettoken123")));
        
        // Test null and empty cases
        String obfuscatedNull = (String) obfuscateMethod.invoke(null, (String) null);
        assertThat("Null input should return null", obfuscatedNull, is(nullValue()));
        
        String obfuscatedEmpty = (String) obfuscateMethod.invoke(null, "");
        assertThat("Empty input should return empty", obfuscatedEmpty, is(""));
    }
}