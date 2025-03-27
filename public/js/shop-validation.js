// Client-side validation for the shop frontend
const shopValidation = {
    // Validate quantity input
    validateQuantity: function(quantity) {
        if (!quantity || isNaN(quantity)) {
            return { isValid: false, message: 'Please enter a valid quantity' };
        }
        if (quantity < 1) {
            return { isValid: false, message: 'Quantity must be at least 1' };
        }
        if (quantity > 100) {
            return { isValid: false, message: 'Maximum quantity is 100' };
        }
        return { isValid: true, message: '' };
    },

    // Show error message
    showError: function(element, message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'shop-error-message';
        errorDiv.textContent = message;
        element.parentNode.appendChild(errorDiv);
        element.classList.add('shop-error');
    },

    // Remove error message
    removeError: function(element) {
        const errorDiv = element.parentNode.querySelector('.shop-error-message');
        if (errorDiv) {
            errorDiv.remove();
        }
        element.classList.remove('shop-error');
    }
};

// Add validation to quantity inputs
document.addEventListener('DOMContentLoaded', function() {
    // Add validation to quantity input in product details
    const quantityInput = document.getElementById('quantity');
    if (quantityInput) {
        quantityInput.addEventListener('input', function() {
            const result = shopValidation.validateQuantity(this.value);
            if (!result.isValid) {
                shopValidation.showError(this, result.message);
            } else {
                shopValidation.removeError(this);
            }
        });
    }

    // Add validation to quantity controls in cart
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('quantity-btn')) {
            const cartItem = e.target.closest('.cart-item');
            if (cartItem) {
                const quantitySpan = cartItem.querySelector('.item-quantity');
                const currentQuantity = parseInt(quantitySpan.textContent);
                const isDecrease = e.target.textContent === '-';
                const newQuantity = isDecrease ? currentQuantity - 1 : currentQuantity + 1;
                
                const result = shopValidation.validateQuantity(newQuantity);
                if (!result.isValid) {
                    e.preventDefault();
                    shopValidation.showError(quantitySpan, result.message);
                } else {
                    shopValidation.removeError(quantitySpan);
                }
            }
        }
    });
}); 