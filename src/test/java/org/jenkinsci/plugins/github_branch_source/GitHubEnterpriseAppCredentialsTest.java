package org.jenkinsci.plugins.github_branch_source;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.Secret;
import org.junit.Test;

public class GitHubEnterpriseAppCredentialsTest {

    @Test
    public void testCredentialCreation() {
        GitHubEnterpriseAppCredentials credentials = new GitHubEnterpriseAppCredentials(
                CredentialsScope.GLOBAL, 
                "test-enterprise-app", 
                "Test GitHub Enterprise App", 
                "12345", 
                Secret.fromString("test-private-key")
        );
        
        assertThat(credentials.getId(), is("test-enterprise-app"));
        assertThat(credentials.getDescription(), is("Test GitHub Enterprise App"));
        assertThat(credentials.getAppID(), is("12345"));
        assertThat(credentials.getPrivateKey(), is(notNullValue()));
        assertThat(credentials.getUsername(), is("12345"));
    }

    @Test
    public void testApiUriSetting() {
        GitHubEnterpriseAppCredentials credentials = GitHubEnterpriseApp.createCredentials("test-id");
        credentials.setApiUri("https://github.enterprise.com/api/v3");
        
        assertThat(credentials.getApiUri(), is("https://github.enterprise.com/api/v3"));
        assertThat(credentials.actualApiUri(), is("https://github.enterprise.com/api/v3"));
    }

    @Test
    public void testDefaultApiUri() {
        GitHubEnterpriseAppCredentials credentials = GitHubEnterpriseApp.createCredentials("test-id");
        
        assertThat(credentials.actualApiUri(), is("https://api.github.com"));
    }

    @Test
    public void testWithApiUri() {
        GitHubEnterpriseAppCredentials originalCredentials = GitHubEnterpriseApp.createCredentials("test-id");
        GitHubEnterpriseAppCredentials clonedCredentials = originalCredentials.withApiUri("https://github.enterprise.com/api/v3");
        
        assertThat(clonedCredentials.getApiUri(), is("https://github.enterprise.com/api/v3"));
        assertThat(clonedCredentials.getId(), is(originalCredentials.getId()));
        assertThat(clonedCredentials.getAppID(), is(originalCredentials.getAppID()));
    }
}
