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

import hudson.EnvVars;
import hudson.Extension;
import hudson.plugins.git.GitException;
import hudson.plugins.git.GitSCM;
import hudson.plugins.git.extensions.GitSCMExtension;
import hudson.plugins.git.extensions.GitSCMExtensionDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jenkinsci.plugins.gitclient.GitClient;

/**
 * A {@link GitSCMExtension} that disables git credential helpers by injecting
 * {@code GIT_CONFIG_COUNT}/{@code GIT_CONFIG_KEY_n}/{@code GIT_CONFIG_VALUE_n}
 * environment variables directly into the {@code CliGitAPIImpl}'s process
 * environment via the {@link #decorate(GitSCM, GitClient)} hook.
 *
 * <p>This is necessary when running in environments like GitHub Codespaces where
 * a system credential helper (e.g. {@code gh auth git-credential}) is configured
 * that intercepts git HTTPS authentication <em>before</em> {@code GIT_ASKPASS}
 * is consulted. By disabling credential helpers, {@code GIT_ASKPASS}
 * (set up by the git-client plugin for {@code StandardUsernamePasswordCredentials})
 * is used instead, which properly provides the passthrough token <strong>and</strong>
 * masks it in console output.</p>
 *
 * <p>The extension sets {@code credential.helper=} (empty value) which, per git
 * documentation, resets the helper list so that no credential helpers run.</p>
 *
 * <p>We use the {@code decorate()} hook instead of {@code populateEnvironmentVariables()}
 * because the latter only populates build-level env vars, which are NOT passed to
 * the git process in Pipeline (WorkflowRun) jobs. The {@code decorate()} hook gives
 * direct access to the {@code GitClient} whose environment IS used by the git process.</p>
 *
 * <p>Requires git 2.31+ for {@code GIT_CONFIG_COUNT} support.</p>
 */
public class PassthroughCredentialHelperDisablerExtension extends GitSCMExtension {

    private static final Logger LOGGER =
            Logger.getLogger(PassthroughCredentialHelperDisablerExtension.class.getName());

    /**
     * Injects {@code GIT_CONFIG_*} environment variables into the GitClient's
     * process environment to disable all credential helpers.
     *
     * <p>Uses reflection to access the package-private {@code environment} field
     * on {@code CliGitAPIImpl}. This is safe because plugin classes are loaded
     * via URLClassLoader, not Java modules, so {@code setAccessible(true)} works.</p>
     */
    @Override
    public GitClient decorate(GitSCM scm, GitClient git)
            throws IOException, InterruptedException, GitException {

        try {
            // CliGitAPIImpl has a package-private field: EnvVars environment
            // This is the environment passed to every git process via launchCommandIn().
            Field envField = git.getClass().getDeclaredField("environment");
            envField.setAccessible(true);
            Object envObj = envField.get(git);

            if (envObj instanceof EnvVars) {
                EnvVars env = (EnvVars) envObj;

                // Read any existing GIT_CONFIG_COUNT to avoid clobbering entries
                String existingCountStr = env.get("GIT_CONFIG_COUNT");
                int idx = 0;
                if (existingCountStr != null) {
                    try {
                        idx = Integer.parseInt(existingCountStr);
                    } catch (NumberFormatException e) {
                        idx = 0;
                    }
                }

                // credential.helper= (empty value) resets the multi-valued helper list,
                // disabling ALL credential helpers from /etc/gitconfig,
                // ~/.gitconfig, and system-level configuration.
                env.put("GIT_CONFIG_KEY_" + idx, "credential.helper");
                env.put("GIT_CONFIG_VALUE_" + idx, "");
                env.put("GIT_CONFIG_COUNT", String.valueOf(idx + 1));

                LOGGER.log(Level.INFO,
                        "Passthrough: disabled credential helpers via GIT_CONFIG environment "
                                + "(index={0}, gitClientClass={1})",
                        new Object[]{idx, git.getClass().getName()});
            } else {
                LOGGER.log(Level.WARNING,
                        "Passthrough: environment field is not EnvVars (type={0})",
                        envObj != null ? envObj.getClass().getName() : "null");
            }
        } catch (NoSuchFieldException e) {
            LOGGER.log(Level.WARNING,
                    "Passthrough: could not find ''environment'' field on {0}. "
                            + "Credential helper disabling skipped. "
                            + "This may cause 403 errors in environments with credential helpers.",
                    git.getClass().getName());
        } catch (IllegalAccessException e) {
            LOGGER.log(Level.WARNING,
                    "Passthrough: could not access ''environment'' field on {0}: {1}. "
                            + "Credential helper disabling skipped.",
                    new Object[]{git.getClass().getName(), e.getMessage()});
        }

        return git;
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
