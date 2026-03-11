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

import com.cloudbees.plugins.credentials.CredentialsSnapshotTaker;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;

/**
 * Snapshot taker for {@link PassthroughTokenCredentials}.
 * 
 * Returns the credential itself (identity function) to prevent the default
 * {@code UsernamePasswordCredentialsSnapshotTaker} from replacing our credential
 * with a generic {@code UsernamePasswordCredentialsImpl}, which could lose
 * important type information needed for the passthrough auth flow.
 * 
 * This mirrors the approach used by {@link GitHubAppCredentialsSnapshotTaker}.
 */
@Extension
public class PassthroughTokenCredentialsSnapshotTaker extends CredentialsSnapshotTaker<PassthroughTokenCredentials> {

    @Override
    public Class<PassthroughTokenCredentials> type() {
        return PassthroughTokenCredentials.class;
    }

    @NonNull
    @Override
    public PassthroughTokenCredentials snapshot(@NonNull PassthroughTokenCredentials credentials) {
        return credentials;
    }
}
