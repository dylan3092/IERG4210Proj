// Function to validate quantity input
function validateQuantity(input) {
    // Sanitize input by removing any non-numeric characters
    input.value = input.value.replace(/[^0-9]/g, '');
    
    let value = parseInt(input.value);
    const errorDiv = input.parentElement.querySelector('.quantity-error');
    
    // Reset error state
    input.classList.remove('shop-error');
    if (errorDiv) {
        errorDiv.textContent = '';
    }

    // Validate the value
    if (isNaN(value) || value < 1) {
        input.value = 1;
        value = 1;
        input.classList.add('shop-error');
        if (errorDiv) {
            errorDiv.textContent = 'Quantity must be a valid number';
        }
        return false;
    } else if (value > 100) {
        input.value = 100;
        value = 100;
        input.classList.add('shop-error');
        if (errorDiv) {
            errorDiv.textContent = 'Maximum quantity is 100';
        }
        return false;
    }

    return value;
}

// Function to add item to cart with validation
function addToCart(productId, quantity) {
    // Get the input element directly
    const quantityInput = document.getElementById('quantity');
    if (!quantityInput) return;
    
    // Get the quantity control container
    const errorDiv = quantityInput.parentElement.querySelector('.quantity-error');
    
    // Validate input value first
    const inputValue = quantityInput.value.trim();
    
    // Check if input is empty or contains non-numeric characters
    if (inputValue === '' || !/^\d+$/.test(inputValue)) {
        // Apply error styling
        quantityInput.classList.add('shop-error');
        if (errorDiv) {
            errorDiv.textContent = 'Quantity must be a valid number';
            errorDiv.classList.add('shop-error-message');
            errorDiv.style.display = 'block';
        }
        return; // Stop execution - don't add to cart
    }
    
    // Parse the value
    const numericValue = parseInt(inputValue, 10);
    
    // Check range
    if (numericValue < 1 || numericValue > 100) {
        // Apply error styling
        quantityInput.classList.add('shop-error');
        if (errorDiv) {
            errorDiv.textContent = numericValue < 1 ? 
                'Quantity must be at least 1' : 
                'Maximum quantity is 100';
            errorDiv.classList.add('shop-error-message');
            errorDiv.style.display = 'block';
        }
        return; // Stop execution - don't add to cart
    }
    
    // Reset error state if input is valid
    quantityInput.classList.remove('shop-error');
    if (errorDiv) {
        errorDiv.textContent = '';
        errorDiv.style.display = 'none';
    }
    
    // If we get here, the input is valid - add to cart
    if (typeof cart !== 'undefined' && typeof cart.addItem === 'function') {
        cart.addItem(productId, numericValue);
    }
} 