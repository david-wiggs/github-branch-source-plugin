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
    
    // Function to check for validation errors and update button states
    function updateButtonStates() {
        // Look for validation error messages in the form
        const errorElements = document.querySelectorAll('.error, .validation-error-area');
        
        // Verbose debugging output
        console.log('=== VALIDATION CHECK START ===');
        console.log('All error elements found:', errorElements.length);
        errorElements.forEach((element, index) => {
            console.log(`Error ${index}:`, {
                text: element.textContent.trim(),
                display: element.style.display,
                visible: element.offsetHeight > 0,
                classes: Array.from(element.classList),
                parentClasses: element.parentNode ? Array.from(element.parentNode.classList) : []
            });
        });
        
        // DOM element hiding logic for demonstration purposes
        const elementsToHide = [];
        errorElements.forEach(element => {
            const errorText = element.textContent.trim();
            if (errorText && errorText.includes('example-hide-trigger')) {
                elementsToHide.push(element);
                console.log('Marking element for hiding:', errorText);
            }
        });
        
        // Hide marked elements
        elementsToHide.forEach(element => {
            if (element.parentNode && element.parentNode.classList.contains('validation-error-area')) {
                element.parentNode.style.display = 'none';
                console.log('Hidden parent element of:', element.textContent.trim());
            } else {
                element.style.display = 'none';
                console.log('Hidden element:', element.textContent.trim());
            }
        });
        
        const hasErrors = Array.from(errorElements).some(element => {
            const hasText = element.textContent.trim() !== '';
            const isVisible = element.style.display !== 'none' && element.offsetHeight > 0;
            const isNotOk = !element.classList.contains('validation-ok');
            
            console.log('Error element validation:', {
                text: element.textContent.trim().substring(0, 50) + '...',
                hasText,
                isVisible,
                isNotOk,
                shouldCount: hasText && isVisible && isNotOk
            });
            
            return hasText && isVisible && isNotOk;
        });
        
        console.log('Validation check result:', hasErrors ? 'ERRORS FOUND' : 'NO ERRORS');
        console.log('Save button found:', !!saveButton);
        console.log('Apply button found:', !!applyButton);
        console.log('=== VALIDATION CHECK END ===');
        
        // Disable buttons if there are validation errors
        if (saveButton) {
            saveButton.disabled = hasErrors;
            if (hasErrors) {
                saveButton.setAttribute('title', 'Cannot save while there are validation errors');
                saveButton.classList.add('disabled');
                console.log('Save button disabled due to validation errors');
            } else {
                saveButton.setAttribute('title', 'Save');
                saveButton.classList.remove('disabled');
                console.log('Save button enabled - no validation errors');
            }
        }
        
        if (applyButton) {
            applyButton.disabled = hasErrors;
            if (hasErrors) {
                applyButton.setAttribute('title', 'Cannot apply while there are validation errors');
                applyButton.classList.add('disabled');
                console.log('Apply button disabled due to validation errors');
            } else {
                applyButton.setAttribute('title', 'Apply');
                applyButton.classList.remove('disabled');
                console.log('Apply button enabled - no validation errors');
            }
        }
    }
    
    // Initial check
    updateButtonStates();
    
    // Monitor for changes in validation state
    const observer = new MutationObserver(function(mutations) {
        console.log('DOM mutation detected, checking validation state...');
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' || mutation.type === 'attributes') {
                // Check if any validation-related elements changed
                const target = mutation.target;
                if (target.classList && (
                    target.classList.contains('error') ||
                    target.classList.contains('validation-error-area') ||
                    target.classList.contains('validation-ok') ||
                    target.closest('.validation-error-area') ||
                    target.closest('.error')
                )) {
                    console.log('Validation-related DOM change detected on:', target);
                    updateButtonStates();
                }
            }
        });
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
            console.log('Validate button clicked, scheduling button state check...');
            // Give the validation a moment to complete, then check button states
            setTimeout(function() {
                console.log('Executing delayed validation check after validate button click');
                updateButtonStates();
            }, 1000);
        });
    } else {
        console.log('Validate button not found');
    }
    
    console.log('GitHub SCM Source JavaScript initialized successfully');
});
