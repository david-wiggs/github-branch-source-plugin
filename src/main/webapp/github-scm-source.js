// Support both normal page load and late dynamic injection (e.g. adding a new GitHub Branch Source after page load)
(function(init){
    if (window.__githubScmSourceInitRun) return; // simple idempotency guard in case adjunct included multiple times
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function(){ if (!window.__githubScmSourceInitRun){ window.__githubScmSourceInitRun=true; init(); }});
    } else {
        window.__githubScmSourceInitRun=true; init();
    }
})(function(){
    // Function to find buttons using multiple possible selectors
    function findButton(type) {
        const selectors = {
            save: [
                "#bottom-sticker > div > button.jenkins-button.jenkins-submit-button.jenkins-button--primary",
                "button.jenkins-submit-button",
                "button[name='Submit']",
                "button[value='Save']",
                "input[type='submit'][value='Save']",
                "button:contains('Save')"
            ],
            apply: [
                "button.jenkins-button.jenkins-apply-button",
                "button[name='Apply']",
                "button[value='Apply']",
                "input[type='submit'][value='Apply']",
                "button:contains('Apply')"
            ]
        };
        
        for (const selector of selectors[type]) {
            const button = document.querySelector(selector);
            if (button) {
                console.log(`Found ${type} button with selector:`, selector);
                return button;
            }
        }
        console.log(`No ${type} button found with any selector`);
        return null;
    }
    
    // Find the Save and Apply buttons using the multi-selector logic
    const saveButton = findButton('save');
    const applyButton = findButton('apply');

    // === Namespace pre-validation additions ===
    // Requirements addressed:
    // 1. Blank URL -> allow save/apply
    // 2. Namespace violation disables save/apply even without pressing validate
    // 3. After pressing validate still disabled on violation (existing logic covers)
    // 4. No duplicate namespace violation errors (reuse existing duplicate hiding logic)

    const NAMESPACE_MISMATCH_TOKEN = 'Repository namespace mismatch';
    const CHECK_ENDPOINT = (window.Jenkins && (window.Jenkins.rootURL || window.Jenkins.projectConfigPageRoot) ? window.Jenkins.rootURL : window.rootURL || '') +
        '/descriptorByName/org.jenkinsci.plugins.github_branch_source.GitHubSCMSource/checkRepositoryUrl?value=';

    function findRepoUrlInputs() {
        return Array.from(document.querySelectorAll("input[name='repositoryUrl'],input[name$='repositoryUrl'],input[name*='repositoryUrl'],input[id$='repositoryUrl'],input[id*='repositoryUrl']"));
    }
    function findRepoUrlInput() { // first match helper for legacy code
        return findRepoUrlInputs()[0] || null;
    }

    // Per-input debounce timers stored on element dataset
    function schedulePreValidationForInput(input, force=false) {
        const value = input.value;
        if (!force && input.dataset.lastNamespaceChecked === value) return;
        input.dataset.lastNamespaceChecked = value;
        if (input._debounceTimer) clearTimeout(input._debounceTimer);
        input._debounceTimer = setTimeout(() => preValidateNamespace(value, force), 400);
    }

    function ensureSingleNamespaceError() {
        const all = Array.from(document.querySelectorAll('.error, .validation-error-area'))
            .filter(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN));
        if (all.length > 1) {
            // Keep first visible; hide others
            let kept = false;
            all.forEach(el => {
                if (!kept && el.offsetHeight > 0 && el.style.display !== 'none') {
                    kept = true;
                } else {
                    el.style.display = 'none';
                }
            });
        }
    }

    function insertOrUpdateNamespaceError(message) {
        // Locate the repositoryUrl f:entry container (nearest .setting or .jenkins-form-item parent)
        const input = findRepoUrlInput();
        if (!input) return;
        let container = input.closest('.setting') || input.closest('.jenkins-form-item') || input.parentElement;
        if (!container) return;

        // Try to find existing namespace error element we created (data attribute marker)
        let existing = container.querySelector('[data-namespace-mismatch="true"]');
        if (!existing) {
            existing = document.createElement('div');
            existing.className = 'validation-error-area error';
            existing.setAttribute('data-namespace-mismatch', 'true');
            // Insert after input
            input.insertAdjacentElement('afterend', existing);
        }
        existing.style.display = '';
        existing.textContent = message;
    }

    function removeNamespaceError() {
        document.querySelectorAll('[data-namespace-mismatch="true"]').forEach(el => el.remove());
    }

    async function preValidateNamespace(value, force = false) {
        // Value-level redundancy handled per-input; keep function simple now.

        if (!value || !value.trim()) {
            // Blank URL allowed, remove any synthetic namespace error
            removeNamespaceError();
            updateButtonStates();
            return;
        }
        const url = CHECK_ENDPOINT + encodeURIComponent(value.trim());
        try {
            const resp = await fetch(url, { method: 'GET', headers: { 'Accept': 'text/html' } });
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const text = await resp.text();
            if (text.includes(NAMESPACE_MISMATCH_TOKEN)) {
                // Extract server message (strip HTML) – simple approach
                const tmp = document.createElement('div');
                tmp.innerHTML = text;
                const errNode = tmp.querySelector('.error, .validation-error-area');
                const msg = errNode ? errNode.textContent.trim() : (NAMESPACE_MISMATCH_TOKEN + ' (validation)');
                insertOrUpdateNamespaceError(msg);
            } else {
                // Server says OK; run client-side fallback namespace validation for new item creation.
                if (!clientNamespaceMatches(value)) {
                    insertOrUpdateNamespaceError(buildClientNamespaceMessage(value));
                } else {
                    removeNamespaceError();
                }
            }
        } catch (e) {
            console.log('Namespace pre-validation fetch failed (non-fatal):', e.message);
            // On fetch failure, still attempt client-side validation so user protected.
            if (value && !clientNamespaceMatches(value)) {
                insertOrUpdateNamespaceError(buildClientNamespaceMessage(value));
            }
        } finally {
            ensureSingleNamespaceError();
            updateButtonStates();
        }
    }

    // --- Client-side fallback namespace validation (no server context) ---
    function extractFolderNamespace() {
        // Use breadcrumbs: collect pr#### and ap#### tokens in order.
        const crumbs = Array.from(document.querySelectorAll('#breadcrumbs li a, #breadcrumbs a')).map(a => a.textContent.trim());
        let pr = null, ap = null;
        crumbs.forEach(txt => {
            if (!pr) {
                const m1 = txt.match(/^pr(\d{3,})$/); if (m1) pr = 'pr' + m1[1];
            }
            if (!ap) {
                const m2 = txt.match(/^ap(\d{3,})$/); if (m2) ap = 'ap' + m2[1];
            }
        });
        return { pr, ap };
    }
    function parseRepositoryName(repoUrl) {
        // Support https and ssh forms
        if (!repoUrl) return '';
        let name = repoUrl.trim();
        const sshMatch = name.match(/^[^:]+:(?:[^/]+)\/([^\s]+)$/); // git@github.com:owner/repo(.git)
        const httpsMatch = name.match(/https?:\/\/[^/]+\/(?:[^/]+)\/([^\s]+)$/);
        if (sshMatch) name = sshMatch[1];
        else if (httpsMatch) name = httpsMatch[1];
        // remove trailing .git
        name = name.replace(/\.git$/,'');
        return name.split('/').pop();
    }
    function clientNamespaceMatches(repoUrl) {
        const { pr, ap } = extractFolderNamespace();
        if (!pr || !ap) return true; // can't evaluate, treat as pass to avoid false block
        const repo = parseRepositoryName(repoUrl);
        if (!repo) return true;
        const expectedPrefix = pr + '-' + ap + '-';
        return repo.startsWith(expectedPrefix);
    }
    function buildClientNamespaceMessage(repoUrl) {
        const { pr, ap } = extractFolderNamespace();
        if (!pr || !ap) return NAMESPACE_MISMATCH_TOKEN + ': Unable to infer folder namespace context.';
        return '❌ ' + NAMESPACE_MISMATCH_TOKEN + ': Expected repository to start with "' + pr + '-' + ap + '-" (derived from folder path).';
    }

    function hookAllRepoUrlInputs() {
        const inputs = findRepoUrlInputs();
        inputs.forEach(input => {
            if (input._namespaceHooked) return;
            input._namespaceHooked = true;
            input.addEventListener('input', e => schedulePreValidationForInput(e.target));
            input.addEventListener('blur', e => preValidateNamespace(e.target.value));
            // Initial check
            schedulePreValidationForInput(input, true);
            console.log('[namespace-validation] Hooked repositoryUrl input:', input.name || input.id);
        });
    }
    // Initial hook
    hookAllRepoUrlInputs();
    // Also attempt re-hook shortly after load in case of delayed widgets
    [300, 800, 1500].forEach(d => setTimeout(hookAllRepoUrlInputs, d));
    // === End namespace pre-validation additions ===
    
    // Robust duplicate removal & button state update
    function dedupeNamespaceErrors() {
        const errs = Array.from(document.querySelectorAll('.error, .validation-error-area'))
            .filter(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN));
        if (errs.length < 2) return;
        // Always keep the first in document order; hide (not remove) the rest so at least one remains.
        let first = errs.shift();
        if (first) {
            first.style.display = '';
            first.removeAttribute('data-namespace-duplicate');
            first.setAttribute('data-namespace-primary', 'true');
        }
        errs.forEach(dup => {
            // Only hide if not primary and still contains token
            if (!dup.hasAttribute('data-namespace-primary')) {
                dup.style.display = 'none';
                dup.setAttribute('data-namespace-duplicate', 'true');
            }
        });
        // Safety: if after operations no visible error remains, unhide the primary
        const anyVisible = Array.from(document.querySelectorAll('.error, .validation-error-area'))
              .some(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN) && el.offsetParent !== null);
        if (!anyVisible && first) {
            first.style.display = '';
        }
    }

    function queryActionButtons() {
        // Re-query each time in case Jenkins re-renders bottom sticker
        const selectors = [
            // Save
            "#bottom-sticker button.jenkins-submit-button",
            "#bottom-sticker button[name='Submit']",
            "#bottom-sticker button[value='Save']",
            "#bottom-sticker input[type='submit'][value='Save']",
            // Apply inside sticker
            "#bottom-sticker button.jenkins-apply-button",
            "#bottom-sticker button[name='Apply']",
            "#bottom-sticker button[value='Apply']",
            "#bottom-sticker input[type='submit'][value='Apply']",
            // Fallbacks (some Jenkins skins place Apply outside or rename classes)
            "button.jenkins-apply-button",
            "button[name='Apply']",
            "button[value='Apply']",
            "input[type='submit'][value='Apply']"
        ];
        const buttons = [];
        selectors.forEach(sel => document.querySelectorAll(sel).forEach(b => buttons.push(b)));
        // Also include originally found apply/save if present
        if (applyButton) buttons.push(applyButton);
        if (saveButton) buttons.push(saveButton);
        const unique = Array.from(new Set(buttons.filter(Boolean)));
        // Log once per update for debugging
        console.log('[namespace-validation] action buttons detected:', unique.map(b=>b.textContent.trim()));
        return unique;
    }

    function disableButton(btn, reason) {
        if (!btn) return;
        btn.disabled = true;
        btn.setAttribute('disabled', 'disabled');
        btn.setAttribute('aria-disabled', 'true');
        btn.classList.add('disabled','jenkins-button--disabled');
        btn.style.pointerEvents = 'none';
        btn.style.opacity = '0.6';
        if (reason) btn.setAttribute('title', reason);
    }
    function enableButton(btn) {
        if (!btn) return;
        btn.disabled = false;
        btn.removeAttribute('disabled');
        btn.setAttribute('aria-disabled', 'false');
        btn.classList.remove('disabled','jenkins-button--disabled');
        btn.style.pointerEvents = '';
        btn.style.opacity = '';
        btn.setAttribute('title', btn.value === 'Apply' || /apply/i.test(btn.textContent) ? 'Apply' : 'Save');
    }

    function hasNamespaceErrorVisible() {
        // Consider synthetic or server errors; allow hidden duplicates to not affect logic
        return Array.from(document.querySelectorAll('.error, .validation-error-area,[data-namespace-mismatch="true"]'))
            .some(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN) && el.style.display !== 'none');
    }

    function stripFormNoValidate() {
        queryActionButtons().forEach(btn => {
            if (btn.hasAttribute('formnovalidate')) {
                btn.removeAttribute('formnovalidate');
            }
        });
    }

    function updateButtonStates() {
        dedupeNamespaceErrors();
        stripFormNoValidate();
        // Mismatch if we have any visible OR synthetic marker awaiting visibility
        const mismatch = hasNamespaceErrorVisible() || !!document.querySelector('[data-namespace-mismatch="true"]');
        const buttons = queryActionButtons();
        console.log('[namespace-validation] mismatch:', mismatch, 'buttons:', buttons.length);
        buttons.forEach(btn => mismatch ? disableButton(btn, 'Cannot save/apply while namespace mismatch exists') : enableButton(btn));
    }
    
    // Initial check
    updateButtonStates();
    
    // Monitor for changes in validation state
    const observer = new MutationObserver(function(mutations) {
        let shouldUpdate = false;
        let newRepoInput = false;
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        const el = node;
                        if (el.matches && (el.matches('button.jenkins-apply-button') || el.matches('button.jenkins-submit-button'))) shouldUpdate = true;
                        if (el.querySelector && el.querySelector('button.jenkins-apply-button, button.jenkins-submit-button')) shouldUpdate = true;
                        if (el.classList && (el.classList.contains('error') || el.classList.contains('validation-error-area'))) shouldUpdate = true;
                        if (el.matches && el.matches("input[name*='repositoryUrl'],input[id*='repositoryUrl']")) newRepoInput = true;
                        if (!newRepoInput && el.querySelector && el.querySelector("input[name*='repositoryUrl'],input[id*='repositoryUrl']")) newRepoInput = true;
                    }
                });
            } else if (mutation.type === 'attributes') {
                const t = mutation.target;
                if (t.classList && (t.classList.contains('error') || t.classList.contains('validation-error-area') || t.classList.contains('validation-ok'))) shouldUpdate = true;
            }
        });
        if (newRepoInput) {
            hookAllRepoUrlInputs();
            shouldUpdate = true;
        }
        if (shouldUpdate) updateButtonStates();
    });
    
    // Start observing the document for changes
    observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class', 'style']
    });
    
    // Also listen for form validation events
    document.addEventListener('jenkins:form-validation', function() {
        console.log('Jenkins form validation event detected');
        updateButtonStates();
    });
    
    // Listen for validation button clicks
    const validateButton = document.getElementById('github-validate-button');
    if (validateButton) {
        validateButton.addEventListener('click', function() {
            console.log('Validate button clicked, forcing pre-validation + scheduling state checks');
            const input = findRepoUrlInput();
            if (input) {
                // Force pre-validation fetch even if value unchanged
                preValidateNamespace(input.value, true);
            }
            [300, 800, 1500].forEach(delay => setTimeout(updateButtonStates, delay));
        });
    } else {
        console.log('Validate button not found');
    }
    
    // Also listen for any validation button clicks in the form (multiple checks)
    document.addEventListener('click', function(event) {
        const target = event.target;
        if (target.tagName === 'BUTTON' && (
            target.textContent.includes('validate') || 
            target.textContent.includes('Validate') ||
            target.classList.contains('validate-button') ||
            target.getAttribute('onclick') && target.getAttribute('onclick').includes('validate')
        )) {
            console.log('Generic validate-like button clicked, triggering forced pre-validation');
            const input = findRepoUrlInput();
            if (input) preValidateNamespace(input.value, true);
            [400, 900, 1600].forEach(d => setTimeout(updateButtonStates, d));
        }
        // Dropdown selection (e.g., Add source -> GitHub) triggers lazy rendering of repositoryUrl input
        if (target.closest && target.closest('.jenkins-dropdown')) {
            console.log('[namespace-validation] Dropdown selection clicked; scheduling repositoryUrl re-hook');
            [50, 200, 600].forEach(d => setTimeout(() => { hookAllRepoUrlInputs(); updateButtonStates(); }, d));
        }
    });
    
    console.log('GitHub SCM Source JavaScript initialized successfully');
});