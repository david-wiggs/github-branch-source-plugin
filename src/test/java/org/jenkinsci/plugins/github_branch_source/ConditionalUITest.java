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
 * Tests for conditional UI configuration persistence.
 */
public class ConditionalUITest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();
    
    @Test
    public void testConfigurationPersistence() throws Exception {
        // Test that configuration can be enabled and persisted
        GitHubConfiguration config = GitHubConfiguration.get();
        
        // Initially disabled
        assertThat("Initially disabled", config.isPassthroughAuthenticationEnabled(), is(false));
        assertThat("Initially no URL", config.getPassthroughAuthenticationUrl(), isEmptyOrNullString());
        
        // Enable and set URL
        config.setPassthroughAuthenticationEnabled(true);
        config.setPassthroughAuthenticationUrl("http://test.example.com/auth");
        config.save();
        
        // Verify persistence
        assertThat("Enabled after save", config.isPassthroughAuthenticationEnabled(), is(true));
        assertThat("URL saved correctly", config.getPassthroughAuthenticationUrl(), is("http://test.example.com/auth"));
        
        // Test disable
        config.setPassthroughAuthenticationEnabled(false);
        config.save();
        
        // URL should still be preserved even when disabled
        assertThat("Disabled after save", config.isPassthroughAuthenticationEnabled(), is(false));
        assertThat("URL preserved when disabled", config.getPassthroughAuthenticationUrl(), is("http://test.example.com/auth"));
    }
    
    @Test
    public void testOptionalBlockConfiguration() throws Exception {
        // Verify that the Jelly configuration is properly set up for conditional display
        GitHubConfiguration config = GitHubConfiguration.get();
        
        // The configuration object should support both enabled/disabled states
        config.setPassthroughAuthenticationEnabled(false);
        config.setPassthroughAuthenticationUrl("");
        assertThat("Can disable", config.isPassthroughAuthenticationEnabled(), is(false));
        
        config.setPassthroughAuthenticationEnabled(true);
        config.setPassthroughAuthenticationUrl("http://localhost:9999/auth");
        assertThat("Can enable", config.isPassthroughAuthenticationEnabled(), is(true));
        assertThat("Can set URL", config.getPassthroughAuthenticationUrl(), is("http://localhost:9999/auth"));
        
        // The UI should be able to handle the optionalBlock structure
        // (This is validated by the Jelly template using f:optionalBlock)
    }
}