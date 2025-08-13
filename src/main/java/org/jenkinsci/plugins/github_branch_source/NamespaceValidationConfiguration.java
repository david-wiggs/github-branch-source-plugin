package org.jenkinsci.plugins.github_branch_source;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Global configuration for namespace validation behavior.
 */
@Extension
public class NamespaceValidationConfiguration extends GlobalConfiguration {

    private boolean enabled = true;
    private String prSegmentRegex = "^pr\\d+$";
    private String apSegmentRegex = "^ap\\d+$";
    /** Template to construct expected repo prefix. Supported tokens: {pr}, {ap}. */
    private String expectedPrefixTemplate = "{pr}-{ap}-";
    /** If true, repo must start with expected prefix; when false, just contain it. */
    private boolean usePrefixMatch = true;
    /** If true, comparisons are case-insensitive. */
    private boolean caseInsensitive = true;
    /** If true, both PR and AP tokens must be present to enforce; otherwise enforce with whichever exists. */
    private boolean requireBothTokens = false;

    public NamespaceValidationConfiguration() {
        load();
    }

    @DataBoundConstructor
    public NamespaceValidationConfiguration(boolean enabled) {
        this.enabled = enabled;
        load();
    }

    public static NamespaceValidationConfiguration get() {
        return GlobalConfiguration.all().get(NamespaceValidationConfiguration.class);
    }

    public boolean isEnabled() { return enabled; }
    @DataBoundSetter public void setEnabled(boolean enabled) { this.enabled = enabled; save(); }

    public String getPrSegmentRegex() { return prSegmentRegex; }
    @DataBoundSetter public void setPrSegmentRegex(String prSegmentRegex) { this.prSegmentRegex = prSegmentRegex; save(); }

    public String getApSegmentRegex() { return apSegmentRegex; }
    @DataBoundSetter public void setApSegmentRegex(String apSegmentRegex) { this.apSegmentRegex = apSegmentRegex; save(); }

    public String getExpectedPrefixTemplate() { return expectedPrefixTemplate; }
    @DataBoundSetter public void setExpectedPrefixTemplate(String expectedPrefixTemplate) { this.expectedPrefixTemplate = expectedPrefixTemplate; save(); }

    public boolean isUsePrefixMatch() { return usePrefixMatch; }
    @DataBoundSetter public void setUsePrefixMatch(boolean usePrefixMatch) { this.usePrefixMatch = usePrefixMatch; save(); }

    public boolean isCaseInsensitive() { return caseInsensitive; }
    @DataBoundSetter public void setCaseInsensitive(boolean caseInsensitive) { this.caseInsensitive = caseInsensitive; save(); }

    public boolean isRequireBothTokens() { return requireBothTokens; }
    @DataBoundSetter public void setRequireBothTokens(boolean requireBothTokens) { this.requireBothTokens = requireBothTokens; save(); }
}
