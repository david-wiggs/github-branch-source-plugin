package org.jenkinsci.plugins.github_branch_source;

import static org.junit.Assert.*;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.FreeStyleProject;
import hudson.util.FormValidation;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * Tests for namespace validation logic in doCheckRepositoryUrl.
 */
public class RepositoryUrlNamespaceValidationTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private GitHubSCMSource.DescriptorImpl descriptor() {
        return j.jenkins.getDescriptorByType(GitHubSCMSource.DescriptorImpl.class);
    }

    @Test
    public void blankUrlIsOk() throws Exception {
        Folder fmr = j.jenkins.createProject(Folder.class, "fmr");
        Folder pr = fmr.createProject(Folder.class, "pr1234");
        Folder ap = pr.createProject(Folder.class, "ap1234");
        FreeStyleProject job = ap.createProject(FreeStyleProject.class, "job1");
        FormValidation v = descriptor().doCheckRepositoryUrl("", job);
        assertEquals(FormValidation.Kind.OK, v.kind);
    }

    @Test
    public void mismatchedNamespaceErrors() throws Exception {
        Folder fmr = j.jenkins.createProject(Folder.class, "fmr");
        Folder pr = fmr.createProject(Folder.class, "pr1234");
        Folder ap = pr.createProject(Folder.class, "ap1234");
        FreeStyleProject job = ap.createProject(FreeStyleProject.class, "job1");
        FormValidation v = descriptor().doCheckRepositoryUrl("https://github.com/org/bookstore", job);
        assertEquals(FormValidation.Kind.ERROR, v.kind);
        assertTrue("Expected mismatch message", v.getMessage().contains("Repository namespace mismatch"));
    }

    @Test
    public void matchingNamespaceOk() throws Exception {
        Folder fmr = j.jenkins.createProject(Folder.class, "fmr");
        Folder pr = fmr.createProject(Folder.class, "pr1234");
        Folder ap = pr.createProject(Folder.class, "ap1234");
        FreeStyleProject job = ap.createProject(FreeStyleProject.class, "job1");
        FormValidation v = descriptor().doCheckRepositoryUrl("https://github.com/org/pr1234-ap1234-bookstore", job);
        assertEquals(FormValidation.Kind.OK, v.kind);
    }
}
