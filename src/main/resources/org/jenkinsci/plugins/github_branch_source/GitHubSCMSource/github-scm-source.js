document.addEventListener("DOMContentLoaded", function() {
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
    const NAMESPACE_MISMATCH_TOKEN = 'Repository namespace mismatch';
    const CHECK_ENDPOINT = (window.Jenkins && (window.Jenkins.rootURL || window.Jenkins.projectConfigPageRoot) ? window.Jenkins.rootURL : window.rootURL || '') +
        '/descriptorByName/org.jenkinsci.plugins.github_branch_source.GitHubSCMSource/checkRepositoryUrl?value=';

    function findRepoUrlInput() {
        return document.querySelector("input[name='repositoryUrl']") ||
               document.querySelector("input[name='_.repositoryUrl']") ||
               document.querySelector("input[id$='repositoryUrl']");
    }

    let repoUrlDebounceTimer = null;
    let lastCheckedValue = null;

    function ensureSingleNamespaceError() {
        const all = Array.from(document.querySelectorAll('.error, .validation-error-area'))
            .filter(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN));
        if (all.length > 1) {
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
        const input = findRepoUrlInput();
        if (!input) return;
        let container = input.closest('.setting') || input.closest('.jenkins-form-item') || input.parentElement;
        if (!container) return;
        let existing = container.querySelector('[data-namespace-mismatch="true"]');
        if (!existing) {
            existing = document.createElement('div');
            existing.className = 'validation-error-area error';
            existing.setAttribute('data-namespace-mismatch', 'true');
            input.insertAdjacentElement('afterend', existing);
        }
        existing.style.display = '';
        existing.textContent = message;
    }

    function removeNamespaceError() {
        document.querySelectorAll('[data-namespace-mismatch="true"]').forEach(el => el.remove());
    }

    async function preValidateNamespace(value, force = false) {
        if (!force && value === lastCheckedValue) return;
        lastCheckedValue = value;
        if (!value || !value.trim()) {
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
                const tmp = document.createElement('div');
                tmp.innerHTML = text;
                const errNode = tmp.querySelector('.error, .validation-error-area');
                const msg = errNode ? errNode.textContent.trim() : (NAMESPACE_MISMATCH_TOKEN + ' (validation)');
                insertOrUpdateNamespaceError(msg);
            } else {
                removeNamespaceError();
            }
        } catch (e) {
            console.log('Namespace pre-validation fetch failed (non-fatal):', e.message);
        } finally {
            ensureSingleNamespaceError();
            updateButtonStates();
        }
    }

    function schedulePreValidation(value) {
        if (repoUrlDebounceTimer) clearTimeout(repoUrlDebounceTimer);
        repoUrlDebounceTimer = setTimeout(() => preValidateNamespace(value), 400);
    }

    function hookRepoUrlInput() {
        const input = findRepoUrlInput();
        if (!input) {
            console.log('Repository URL input not yet found for pre-validation');
            return false;
        }
        if (input._namespaceHooked) return true;
        input._namespaceHooked = true;
        input.addEventListener('input', e => schedulePreValidation(e.target.value));
        input.addEventListener('blur', e => preValidateNamespace(e.target.value));
        schedulePreValidation(input.value || '');
        console.log('Repository URL input hooked for namespace pre-validation');
        return true;
    }

    if (!hookRepoUrlInput()) {
        let attempts = 0;
        const retryTimer = setInterval(() => {
            attempts++;
            if (hookRepoUrlInput() || attempts > 20) {
                clearInterval(retryTimer);
            }
        }, 500);
    }
    // === End namespace pre-validation additions ===
    
    function dedupeNamespaceErrors() {
        const errs = Array.from(document.querySelectorAll('.error, .validation-error-area'))
            .filter(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN));
        if (errs.length < 2) return;
        let first = errs.shift();
        if (first) {
            first.style.display='';
            first.removeAttribute('data-namespace-duplicate');
            first.setAttribute('data-namespace-primary','true');
        }
        errs.forEach(dup => {
            if (!dup.hasAttribute('data-namespace-primary')) {
                dup.style.display='none';
                dup.setAttribute('data-namespace-duplicate','true');
            }
        });
        const anyVisible = Array.from(document.querySelectorAll('.error, .validation-error-area'))
            .some(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN) && el.offsetParent !== null);
        if (!anyVisible && first) {
            first.style.display='';
        }
    }
    function queryActionButtons() {
        const selectors = [
            "#bottom-sticker button.jenkins-submit-button",
            "#bottom-sticker button[name='Submit']",
            "#bottom-sticker button[value='Save']",
            "#bottom-sticker input[type='submit'][value='Save']",
            "#bottom-sticker button.jenkins-apply-button",
            "#bottom-sticker button[name='Apply']",
            "#bottom-sticker button[value='Apply']",
            "#bottom-sticker input[type='submit'][value='Apply']",
            "button.jenkins-apply-button",
            "button[name='Apply']",
            "button[value='Apply']",
            "input[type='submit'][value='Apply']"
        ];
        const buttons = [];
        selectors.forEach(sel => document.querySelectorAll(sel).forEach(b => buttons.push(b)));
        if (applyButton) buttons.push(applyButton);
        if (saveButton) buttons.push(saveButton);
        const unique = Array.from(new Set(buttons.filter(Boolean)));
        console.log('[namespace-validation] action buttons detected:', unique.map(b=>b.textContent.trim()));
        return unique;
    }
    function disableButton(btn, reason) {
        if (!btn) return;
        btn.disabled = true;
        btn.setAttribute('disabled','disabled');
        btn.setAttribute('aria-disabled','true');
        btn.classList.add('disabled','jenkins-button--disabled');
        btn.style.pointerEvents='none';
        btn.style.opacity='0.6';
        if (reason) btn.setAttribute('title', reason);
    }
    function enableButton(btn) {
        if (!btn) return;
        btn.disabled = false;
        btn.removeAttribute('disabled');
        btn.setAttribute('aria-disabled','false');
        btn.classList.remove('disabled','jenkins-button--disabled');
        btn.style.pointerEvents='';
        btn.style.opacity='';
        btn.setAttribute('title', /apply/i.test(btn.textContent)?'Apply':'Save');
    }
    function hasNamespaceErrorVisible() {
        return Array.from(document.querySelectorAll('.error, .validation-error-area,[data-namespace-mismatch="true"]'))
            .some(el => el.textContent && el.textContent.includes(NAMESPACE_MISMATCH_TOKEN) && el.style.display !== 'none');
    }
    function stripFormNoValidate() {
        queryActionButtons().forEach(btn => btn.removeAttribute('formnovalidate'));
    }
    function updateButtonStates() {
        dedupeNamespaceErrors();
        stripFormNoValidate();
        const mismatch = hasNamespaceErrorVisible() || !!document.querySelector('[data-namespace-mismatch="true"]');
        const buttons = queryActionButtons();
        console.log('[namespace-validation] mismatch:', mismatch, 'buttons:', buttons.length);
        buttons.forEach(btn => mismatch ? disableButton(btn, 'Cannot save/apply while namespace mismatch exists') : enableButton(btn));
    }
    
    // Initial check
    updateButtonStates();
    
    // Monitor for changes in validation state
    const observer = new MutationObserver(function(mutations) {
        let should = false;
        mutations.forEach(m => {
            if (m.type === 'childList') {
                m.addedNodes.forEach(n => {
                    if (n.nodeType === 1) {
                        const el = n;
                        if (el.matches && (el.matches('button.jenkins-apply-button') || el.matches('button.jenkins-submit-button'))) should = true;
                        if (el.querySelector && el.querySelector('button.jenkins-apply-button, button.jenkins-submit-button')) should = true;
                        if (el.classList && (el.classList.contains('error') || el.classList.contains('validation-error-area'))) should = true;
                    }
                });
            } else if (m.type === 'attributes') {
                const t = m.target;
                if (t.classList && (t.classList.contains('error') || t.classList.contains('validation-error-area') || t.classList.contains('validation-ok'))) should = true;
            }
        });
        if (should) updateButtonStates();
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
            console.log('Validate button clicked, forcing pre-validation');
            const input = findRepoUrlInput();
            if (input) preValidateNamespace(input.value, true);
            [300, 800, 1500].forEach(d => setTimeout(updateButtonStates, d));
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
            console.log('Generic validate-like button clicked; forcing pre-validation');
            const input = findRepoUrlInput();
            if (input) preValidateNamespace(input.value, true);
            [400, 900, 1600].forEach(d => setTimeout(updateButtonStates, d));
        }
    });
    
    console.log('GitHub SCM Source JavaScript initialized successfully');
});
