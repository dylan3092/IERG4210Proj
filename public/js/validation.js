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
    }
};

// Add event listeners to forms
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const inputs = form.querySelectorAll('input, textarea, select');
            let isValid = true;
            let errorMessage = '';

            inputs.forEach(input => {
                const value = input.value;
                let validationResult;

                // Determine which validation to use based on input type or name
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
                }

                if (validationResult && !validationResult.isValid) {
                    isValid = false;
                    errorMessage = validationResult.message;
                    input.classList.add('error');
                } else {
                    input.classList.remove('error');
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert(errorMessage);
            }
        });
    });
}); 