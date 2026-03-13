/*
 * The MIT License
 *
 * Copyright 2024 Jenkins project contributors
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

import hudson.Extension;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.extensions.GitSCMExtension;
import hudson.plugins.git.extensions.GitSCMExtensionDescriptor;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A {@link GitSCMExtension} that disables git credential helpers via
 * {@code GIT_CONFIG_COUNT}/{@code GIT_CONFIG_KEY_n}/{@code GIT_CONFIG_VALUE_n}
 * environment variables.
 *
 * <p>This is necessary when running in environments like GitHub Codespaces where
 * a system credential helper (e.g. {@code gh auth git-credential}) is configured
 * that intercepts git HTTPS authentication <em>before</em> {@code GIT_ASKPASS}
 * is consulted. By disabling credential helpers via environment, {@code GIT_ASKPASS}
 * (set up by the git-client plugin for {@code StandardUsernamePasswordCredentials})
 * is used instead, which properly provides the passthrough token <strong>and</strong>
 * masks it in console output.</p>
 *
 * <p>The extension sets {@code credential.helper=} (empty value) which, per git
 * documentation, resets the helper list so that no credential helpers run.</p>
 *
 * <p>Requires git 2.31+ for {@code GIT_CONFIG_COUNT} support. Git 2.52.0 is
 * confirmed on the Jenkins agent.</p>
 */
public class PassthroughCredentialHelperDisablerExtension extends GitSCMExtension {

    private static final Logger LOGGER =
            Logger.getLogger(PassthroughCredentialHelperDisablerExtension.class.getName());

    @Override
    public void populateEnvironmentVariables(GitSCM scm, Map<String, String> env) {
        // Read any existing GIT_CONFIG_COUNT to avoid clobbering entries
        // set by other extensions or the environment.
        String existingCountStr = env.get("GIT_CONFIG_COUNT");
        int idx = 0;
        if (existingCountStr != null) {
            try {
                idx = Integer.parseInt(existingCountStr);
            } catch (NumberFormatException e) {
                // If unparseable, start from 0 (will overwrite whatever was there)
                idx = 0;
            }
        }

        // credential.helper= (empty value) resets the multi-valued helper list,
        // effectively disabling ALL credential helpers from /etc/gitconfig,
        // ~/.gitconfig, and system-level configuration.
        env.put("GIT_CONFIG_KEY_" + idx, "credential.helper");
        env.put("GIT_CONFIG_VALUE_" + idx, "");
        env.put("GIT_CONFIG_COUNT", String.valueOf(idx + 1));

        LOGGER.log(Level.FINE,
                "Passthrough: disabled credential helpers via GIT_CONFIG environment "
                        + "(index={0})", idx);
    }

    /**
     * Descriptor is required for XStream serialization/deserialization of the
     * {@link GitSCM} object that contains this extension. Marked as
     * {@link Extension} so Jenkins can resolve it during deserialization.
     */
    @Extension
    public static class DescriptorImpl extends GitSCMExtensionDescriptor {
        @Override
        public String getDisplayName() {
            return "Passthrough: disable credential helpers";
        }
    }
}
