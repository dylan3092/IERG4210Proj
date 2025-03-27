// Input validation and sanitization functions
const validation = {
    // Sanitize input by removing potentially dangerous characters
    sanitizeInput: function(input) {
        return input.replace(/[<>]/g, '');
    },

    // Validate product name
    validateProductName: function(name) {
        if (!name || name.trim().length === 0) {
            return { isValid: false, message: 'Product name is required' };
        }
        if (name.length > 100) {
            return { isValid: false, message: 'Product name must be less than 100 characters' };
        }
        if (!/^[A-Za-z0-9\s-]+$/.test(name)) {
            return { isValid: false, message: 'Product name can only contain letters, numbers, spaces, and hyphens' };
        }
        return { isValid: true, message: '' };
    },

    // Validate price
    validatePrice: function(price) {
        if (!price || isNaN(price)) {
            return { isValid: false, message: 'Price must be a valid number' };
        }
        if (price < 0) {
            return { isValid: false, message: 'Price cannot be negative' };
        }
        if (price > 1000000) {
            return { isValid: false, message: 'Price must be less than 1,000,000' };
        }
        return { isValid: true, message: '' };
    },

    // Validate category name
    validateCategoryName: function(name) {
        if (!name || name.trim().length === 0) {
            return { isValid: false, message: 'Category name is required' };
        }
        if (name.length > 50) {
            return { isValid: false, message: 'Category name must be less than 50 characters' };
        }
        if (!/^[A-Za-z0-9\s-]+$/.test(name)) {
            return { isValid: false, message: 'Category name can only contain letters, numbers, spaces, and hyphens' };
        }
        return { isValid: true, message: '' };
    },

    // Validate quantity
    validateQuantity: function(quantity) {
        if (!quantity || isNaN(quantity)) {
            return { isValid: false, message: 'Quantity must be a valid number' };
        }
        if (quantity < 1) {
            return { isValid: false, message: 'Quantity must be at least 1' };
        }
        if (quantity > 100) {
            return { isValid: false, message: 'Quantity cannot exceed 100' };
        }
        return { isValid: true, message: '' };
    },

    // Validate description
    validateDescription: function(description) {
        if (!description || description.trim().length === 0) {
            return { isValid: false, message: 'Description is required' };
        }
        if (description.length < 10) {
            return { isValid: false, message: 'Description must be at least 10 characters' };
        }
        if (description.length > 1000) {
            return { isValid: false, message: 'Description must be less than 1000 characters' };
        }
        return { isValid: true, message: '' };
    }
};

// Create and show error message element
function showError(input, message) {
    const formGroup = input.closest('.form-group');
    let errorDiv = formGroup.querySelector('.error-message');
    
    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        formGroup.appendChild(errorDiv);
    }
    
    errorDiv.textContent = message;
    input.classList.add('error');
}

// Remove error message element
function removeError(input) {
    const formGroup = input.closest('.form-group');
    const errorDiv = formGroup.querySelector('.error-message');
    if (errorDiv) {
        errorDiv.remove();
    }
    input.classList.remove('error');
}

// Add event listeners to forms
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input, textarea, select');
        
        // Add real-time validation on input
        inputs.forEach(input => {
            input.addEventListener('input', function() {
                const value = this.value;
                let validationResult;

                // Determine which validation to use based on input type or name
                switch(this.type) {
                    case 'number':
                        if (this.name.includes('price')) {
                            validationResult = validation.validatePrice(value);
                        } else if (this.name.includes('quantity')) {
                            validationResult = validation.validateQuantity(value);
                        }
                        break;
                    case 'text':
                        if (this.name.includes('category')) {
                            validationResult = validation.validateCategoryName(value);
                        } else if (this.name.includes('product')) {
                            validationResult = validation.validateProductName(value);
                        }
                        break;
                    case 'textarea':
                        if (this.name.includes('description')) {
                            validationResult = validation.validateDescription(value);
                        }
                        break;
                }

                if (validationResult) {
                    if (!validationResult.isValid) {
                        showError(this, validationResult.message);
                    } else {
                        removeError(this);
                    }
                }
            });
        });

        // Form submission validation
        form.addEventListener('submit', function(e) {
            let isValid = true;
            let firstInvalidInput = null;

            inputs.forEach(input => {
                const value = input.value;
                let validationResult;

                switch(input.type) {
                    case 'number':
                        if (input.name.includes('price')) {
                            validationResult = validation.validatePrice(value);
                        } else if (input.name.includes('quantity')) {
                            validationResult = validation.validateQuantity(value);
                        }
                        break;
                    case 'text':
                        if (input.name.includes('category')) {
                            validationResult = validation.validateCategoryName(value);
                        } else if (input.name.includes('product')) {
                            validationResult = validation.validateProductName(value);
                        }
                        break;
                    case 'textarea':
                        if (input.name.includes('description')) {
                            validationResult = validation.validateDescription(value);
                        }
                        break;
                }

                if (validationResult && !validationResult.isValid) {
                    isValid = false;
                    if (!firstInvalidInput) {
                        firstInvalidInput = input;
                    }
                    showError(input, validationResult.message);
                } else {
                    removeError(input);
                }
            });

            if (!isValid) {
                e.preventDefault();
                if (firstInvalidInput) {
                    firstInvalidInput.focus();
                }
            }
        });
    });
}); 