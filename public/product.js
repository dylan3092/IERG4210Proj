document.addEventListener('DOMContentLoaded', async () => {
    // Get product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('product');

    if (!productId) {
        window.location.href = '/';
        return;
    }

    try {
        // Fetch categories for sidebar
        const categoriesResponse = await fetch(`${BASE_URL}/api/categories`);
        const categories = await categoriesResponse.json();
        
        const categoriesList = document.querySelector('aside ul');
        categoriesList.innerHTML = categories.map(category => `
            <li><a href="/?category=${sanitize.attribute(category.catid)}">${sanitize.html(category.name)}</a></li>
        `).join('');

        // Fetch product details
        const productResponse = await fetch(`${BASE_URL}/api/products/${encodeURIComponent(productId)}`);
        if (!productResponse.ok) {
            throw new Error('Product not found');
        }
        
        const product = await productResponse.json();
        
        // Update page title - Sanitize product name
        document.title = `${sanitize.html(product.name)} - Neon Shopping`;

        // DEBUG: Log the product object to see its structure
        console.log('Product object in product.js:', JSON.stringify(product, null, 2));

        // Update breadcrumb using category_name from API - Sanitize all values
        const breadcrumb = document.querySelector('.breadcrumb');
        breadcrumb.innerHTML = `
            <a href="/">Home</a>
            <span class="separator"> > </span>
            <a href="/?category=${sanitize.attribute(product.catid)}">${sanitize.html(product.category_name)}</a>
            <span class="separator"> > </span>
            <span>${sanitize.html(product.name)}</span>
        `;

        // Display product details - Sanitize all values
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = `
            <div class="product-image">
                <img src="${product.image ? 
                    sanitize.url(`${BASE_URL}/uploads/${product.image}`) : 
                    'images/default.jpg'}" 
                    alt="${sanitize.attribute(product.name)}">
            </div>
            <div class="product-info">
                <h1>${sanitize.html(product.name)}</h1>
                <p class="category">Category: ${sanitize.html(product.category_name)}</p>
                <p class="price" id="product-price">$${sanitize.html(Number(product.price).toFixed(2))}</p>
                <p class="description">${sanitize.html(product.description)}</p>
                <div class="purchase-controls">
                    <div class="quantity-control">
                        <input type="number" 
                               id="quantity" 
                               value="1" 
                               min="1" 
                               max="100"
                               oninput="validateQuantity(this)"
                               onkeypress="return event.charCode >= 48 && event.charCode <= 57">
                        <div class="quantity-error"></div>
                    </div>
                    <button onclick="addToCart(${sanitize.html(product.pid)}, document.getElementById('quantity').value)">
                        Add to Cart
                    </button>
                </div>
            </div>
        `;

        // --- NEW: Display Discount Description ---
        const productInfoDiv = productDetails.querySelector('.product-info'); // Get the .product-info div
        const priceElement = productDetails.querySelector('#product-price'); // Get the price element by its new ID

        if (product.discount && product.discount.description && productInfoDiv && priceElement) {
            const discountElement = document.createElement('p');
            discountElement.className = 'product-discount-offer';
            discountElement.textContent = sanitize.html(product.discount.description); // Sanitize the discount description
            
            // Insert the discount element after the price element
            priceElement.insertAdjacentElement('afterend', discountElement);
            console.log('Discount displayed:', product.discount.description);
        }
        // --- END: Display Discount Description ---

        // Add event listener for quantity input
        const quantityInput = document.getElementById('quantity');
        if (quantityInput) {
            quantityInput.addEventListener('input', function() {
                validateQuantity(this);
            });
        }

    } catch (error) {
        console.error('Error:', error);
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = '<p class="error">Product not found</p>';
    }
});

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