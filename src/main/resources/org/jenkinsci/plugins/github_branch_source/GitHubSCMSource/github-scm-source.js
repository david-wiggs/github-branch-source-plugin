// Support both normal page load and dynamic late injection (new source panel after initial load)
(function(init){
    if (window.__githubScmSourceAdjunctInit) return;
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function(){ if(!window.__githubScmSourceAdjunctInit){ window.__githubScmSourceAdjunctInit=true; init(); }});
    } else { window.__githubScmSourceAdjunctInit=true; init(); }
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
    const NAMESPACE_MISMATCH_TOKEN = 'Repository namespace mismatch';
    const ROOT_URL = (window.Jenkins && (window.Jenkins.rootURL || window.Jenkins.projectConfigPageRoot) ? window.Jenkins.rootURL : window.rootURL || '');
    const CHECK_ENDPOINT = ROOT_URL + '/descriptorByName/org.jenkinsci.plugins.github_branch_source.GitHubSCMSource/checkRepositoryUrl?value=';
    const CFG_ENDPOINT = ROOT_URL + '/descriptorByName/org.jenkinsci.plugins.github_branch_source.GitHubSCMSource/getNamespaceValidationConfig';
    let NS_CFG = { enabled:true, prSegmentRegex:'^pr\\d+$', apSegmentRegex:'^ap\\d+$', expectedPrefixTemplate:'{pr}-{ap}-', usePrefixMatch:true, caseInsensitive:true, requireBothTokens:false, _loaded:false };
    (async function(){ try{ const r=await fetch(CFG_ENDPOINT,{headers:{'Accept':'application/json'}}); if(r.ok){ const j=await r.json(); NS_CFG=Object.assign(NS_CFG,j,{_loaded:true}); console.log('[namespace-validation] loaded config:', NS_CFG);} }catch(e){} })();

    function findRepoUrlInputs() {
        return Array.from(document.querySelectorAll("input[name='repositoryUrl'],input[name$='repositoryUrl'],input[name*='repositoryUrl'],input[id$='repositoryUrl'],input[id*='repositoryUrl']"));
    }
    function findRepoUrlInput(){return findRepoUrlInputs()[0]||null;}
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
                if (!clientNamespaceMatches(value)) {
                    insertOrUpdateNamespaceError(buildClientNamespaceMessage(value));
                } else {
                    removeNamespaceError();
                }
            }
        } catch (e) {
            console.log('Namespace pre-validation fetch failed (non-fatal):', e.message);
            if (value && !clientNamespaceMatches(value)) {
                insertOrUpdateNamespaceError(buildClientNamespaceMessage(value));
            }
        } finally {
            ensureSingleNamespaceError();
            updateButtonStates();
        }
    }

    function extractFolderNamespace(){ const crumbs=Array.from(document.querySelectorAll('#breadcrumbs li a, #breadcrumbs a')).map(a=>a.textContent.trim()); let pr=null, ap=null; const prRe=new RegExp(NS_CFG.prSegmentRegex, NS_CFG.caseInsensitive?'i':''); const apRe=new RegExp(NS_CFG.apSegmentRegex, NS_CFG.caseInsensitive?'i':''); crumbs.forEach(txt=>{ if(!pr && prRe.test(txt)) pr=txt; if(!ap && apRe.test(txt)) ap=txt; }); return {pr, ap}; }
    function parseRepositoryName(repoUrl) {
        if (!repoUrl) return '';
        let name = repoUrl.trim();
        const sshMatch = name.match(/^[^:]+:(?:[^/]+)\/([^\s]+)$/);
        const httpsMatch = name.match(/https?:\/\/[^/]+\/(?:[^/]+)\/([^\s]+)$/);
        if (sshMatch) name = sshMatch[1]; else if (httpsMatch) name = httpsMatch[1];
        name = name.replace(/\.git$/,'');
        return name.split('/').pop();
    }
    function buildExpectedFromTemplate(pr, ap){ return NS_CFG.expectedPrefixTemplate.replace('{pr}', pr||'').replace('{ap}', ap||''); }
    function clientNamespaceMatches(repoUrl){ if(!NS_CFG.enabled) return true; const {pr, ap}=extractFolderNamespace(); if (NS_CFG.requireBothTokens && (!pr || !ap)) return true; if(!pr && !ap) return true; const repo=parseRepositoryName(repoUrl); if(!repo) return true; const expected=buildExpectedFromTemplate(pr, ap); if(NS_CFG.caseInsensitive){ const r=repo.toLowerCase(); const e=expected.toLowerCase(); return NS_CFG.usePrefixMatch ? r.startsWith(e) : r.includes(e);} return NS_CFG.usePrefixMatch ? repo.startsWith(expected) : repo.includes(expected); }
    function buildClientNamespaceMessage(repoUrl){ if(!NS_CFG.enabled) return ''; const {pr, ap}=extractFolderNamespace(); if(!pr && !ap) return NAMESPACE_MISMATCH_TOKEN + ': Unable to infer folder namespace context.'; const expected=buildExpectedFromTemplate(pr, ap); return '❌ ' + NAMESPACE_MISMATCH_TOKEN + ': Expected repository to ' + (NS_CFG.usePrefixMatch ? 'start with' : 'contain') + ' "' + expected + '" (derived from folder path).'; }

    function schedulePreValidation(value) {
        if (repoUrlDebounceTimer) clearTimeout(repoUrlDebounceTimer);
        repoUrlDebounceTimer = setTimeout(() => preValidateNamespace(value), 400);
    }

    function hookAllRepoUrlInputs() {
        const inputs = findRepoUrlInputs();
        inputs.forEach(input => {
            if (input._namespaceHooked) return;
            input._namespaceHooked = true;
            input.addEventListener('input', e => schedulePreValidationForInput(e.target));
            input.addEventListener('blur', e => preValidateNamespace(e.target.value));
            schedulePreValidationForInput(input, true);
            console.log('[namespace-validation] Hooked repositoryUrl input:', input.name || input.id);
        });
    }
    hookAllRepoUrlInputs();
    [300,800,1500].forEach(d=>setTimeout(hookAllRepoUrlInputs,d));
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
        let should = false; let newRepo=false;
        mutations.forEach(m => {
            if (m.type === 'childList') {
                m.addedNodes.forEach(n => { if (n.nodeType===1){ const el=n; if (el.matches && (el.matches('button.jenkins-apply-button')||el.matches('button.jenkins-submit-button'))) should=true; if (el.querySelector && el.querySelector('button.jenkins-apply-button, button.jenkins-submit-button')) should=true; if (el.classList && (el.classList.contains('error')||el.classList.contains('validation-error-area'))) should=true; if (el.matches && el.matches("input[name*='repositoryUrl'],input[id*='repositoryUrl']")) newRepo=true; if(!newRepo && el.querySelector && el.querySelector("input[name*='repositoryUrl'],input[id*='repositoryUrl']")) newRepo=true; }});
            } else if (m.type==='attributes') {
                const t=m.target; if (t.classList && (t.classList.contains('error')||t.classList.contains('validation-error-area')||t.classList.contains('validation-ok'))) should=true;
            }
        });
        if(newRepo){ hookAllRepoUrlInputs(); should=true; }
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
        if (target.closest && target.closest('.jenkins-dropdown')) {
            console.log('[namespace-validation] Dropdown selection clicked; scheduling repositoryUrl re-hook');
            [50,200,600].forEach(d=>setTimeout(()=>{hookAllRepoUrlInputs(); updateButtonStates();},d));
        }
    });
    
    console.log('GitHub SCM Source JavaScript initialized successfully');
});
