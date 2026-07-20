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
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class PassthroughAuthResultTest {
    
    @Test
    public void testBasicFunctionality() {
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token",
            Arrays.asList("metadata:write", "contents:write"),
            "push",
            Arrays.asList("group1", "group2"),
            Arrays.asList("team1", "team2")
        );
        
        assertThat(result.getToken(), is("test-token"));
        assertThat(result.getScopes(), contains("metadata:write", "contents:write"));
        assertThat(result.getPermissions(), is("push"));
        assertThat(result.getUserGroups(), contains("group1", "group2"));
        assertThat(result.getMatchingTeams(), contains("team1", "team2"));
    }
    
    @Test
    public void testDisplayInfo() {
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token",
            Arrays.asList("metadata:write", "contents:write", "issues:write"),
            "push",
            Arrays.asList("azgALMAP12345SVCDeveloper"),
            Arrays.asList("azgALMAP12345SCMDeveloper")
        );
        
        String displayInfo = result.getDisplayInfo();
        assertThat(displayInfo, containsString("Scopes: [metadata:write, contents:write, issues:write]"));
        assertThat(displayInfo, containsString("Permissions: push"));
        assertThat(displayInfo, containsString("User Groups: [azgALMAP12345SVCDeveloper]"));
        assertThat(displayInfo, containsString("Matching Teams: [azgALMAP12345SCMDeveloper]"));
    }
    
    @Test
    public void testDisplayInfoWithEmptyValues() {
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token",
            Collections.emptyList(),
            "",
            Collections.emptyList(),
            Collections.emptyList()
        );
        
        String displayInfo = result.getDisplayInfo();
        assertThat(displayInfo, is(""));
    }
    
    @Test
    public void testDisplayInfoWithPartialValues() {
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token",
            Arrays.asList("read", "write"),
            null,
            Collections.emptyList(),
            Arrays.asList("dev-team")
        );
        
        String displayInfo = result.getDisplayInfo();
        assertThat(displayInfo, containsString("Scopes: [read, write]"));
        assertThat(displayInfo, containsString("Matching Teams: [dev-team]"));
        assertThat(displayInfo, not(containsString("Permissions")));
        assertThat(displayInfo, not(containsString("User Groups")));
    }

    @Test
    public void notStaleWhenExpiryFarInFuture() {
        long future = System.currentTimeMillis() + Duration.ofHours(1).toMillis();
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token", Collections.emptyList(), "push",
            Collections.emptyList(), Collections.emptyList(), future);

        assertThat(result.getExpiresAtEpochMilli(), is(future));
        assertThat(result.isStale(), is(false));
    }

    @Test
    public void staleWhenExpiryInThePast() {
        long past = System.currentTimeMillis() - 1000L;
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token", Collections.emptyList(), "push",
            Collections.emptyList(), Collections.emptyList(), past);

        assertThat(result.isStale(), is(true));
    }

    @Test
    public void staleWhenWithinRefreshMargin() {
        // Expires in one minute; the default refresh margin is five minutes, so it is already stale.
        long soon = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        PassthroughAuthResult result = new PassthroughAuthResult(
            "test-token", Collections.emptyList(), "push",
            Collections.emptyList(), Collections.emptyList(), soon);

        assertThat(result.isStale(), is(true));
    }

    @Test
    public void fallbackLifetimeUsedWhenExpiryUnknown() {
        long originalFallback = PassthroughAuthResult.FALLBACK_LIFETIME_MILLIS;
        try {
            // A fresh token with no reported expiry is not stale while within the fallback lifetime.
            PassthroughAuthResult.FALLBACK_LIFETIME_MILLIS = Duration.ofMinutes(45).toMillis();
            PassthroughAuthResult fresh = new PassthroughAuthResult(
                "test-token", Collections.emptyList(), "push",
                Collections.emptyList(), Collections.emptyList());
            assertThat(fresh.getExpiresAtEpochMilli(), is(PassthroughAuthResult.EXPIRY_UNKNOWN));
            assertThat(fresh.isStale(), is(false));

            // With a zero fallback lifetime it is immediately considered stale.
            PassthroughAuthResult.FALLBACK_LIFETIME_MILLIS = 0L;
            PassthroughAuthResult stale = new PassthroughAuthResult(
                "test-token", Collections.emptyList(), "push",
                Collections.emptyList(), Collections.emptyList());
            assertThat(stale.isStale(), is(true));
        } finally {
            PassthroughAuthResult.FALLBACK_LIFETIME_MILLIS = originalFallback;
        }
    }
}