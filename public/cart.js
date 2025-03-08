// Cart data structure
let cart = {
    items: {} // Using object with pid as key for easier lookup
};

// Initialize cart functionality
document.addEventListener('DOMContentLoaded', async () => {
    // Load cart data immediately before showing UI
    await loadCart();
    
    // Initialize cart UI only after data is loaded
    initializeCartUI();
    await updateCartDisplay();
});

function initializeCartUI() {
    const cartSection = document.querySelector('.shopping-cart');
    const cartDetails = document.querySelector('.cart-details');

    if (cartSection && cartDetails) {
        // Use CSS transitions for smooth show/hide
        cartDetails.style.transition = 'opacity 0.3s';
        
        cartSection.addEventListener('mouseenter', () => {
            cartDetails.style.opacity = '1';
            cartDetails.style.display = 'block';
        });

        cartSection.addEventListener('mouseleave', () => {
            cartDetails.style.opacity = '0';
            setTimeout(() => {
                cartDetails.style.display = 'none';
            }, 300);
        });
    }
}

// Add to cart function
async function addToCart(productId, quantity = 1) {
    console.log('Adding to cart:', productId, quantity);
    try {
        quantity = parseInt(quantity);
        if (isNaN(quantity) || quantity < 1) quantity = 1;

        // Fetch product details first to verify it exists
        const productDetails = await updateProductDetails(productId);
        if (!productDetails) {
            throw new Error('Product not found');
        }

        // Update cart
        if (cart.items[productId]) {
            cart.items[productId].quantity += quantity;
        } else {
            cart.items[productId] = {
                quantity: quantity,
                name: productDetails.name,
                price: Number(productDetails.price)
            };
        }

        // Save to localStorage
        saveCart();
        
        // Update display
        await updateCartDisplay();
        
        // Show feedback
        showAddedFeedback();
        
    } catch (error) {
        console.error('Error adding to cart:', error);
    }
}

// Fetch product details via AJAX
async function updateProductDetails(productId) {
    console.log('Fetching product details for:', productId);
    try {
        const response = await fetch(`${BASE_URL}/api/products/${productId}`);
        if (!response.ok) {
            throw new Error('Product not found');
        }
        
        const product = await response.json();
        console.log('Received product details:', product);
        return product;
        
    } catch (error) {
        console.error('Error fetching product details:', error);
        return null;
    }
}

// Update cart display
async function updateCartDisplay() {
    const cartList = document.getElementById('cart-items');
    const cartTotal = document.getElementById('cart-total');
    const checkoutBtn = document.getElementById('checkout-btn');
    
    if (!cartList || !cartTotal || !checkoutBtn) return;

    // Calculate total
    const total = Object.entries(cart.items).reduce(
        (sum, [_, item]) => sum + (Number(item.price) * item.quantity), 
        0
    );

    // Update display
    cartList.innerHTML = Object.entries(cart.items).map(([pid, item]) => `
        <li>
            <span class="item-name">${item.name}</span>
            <div class="item-controls">
                <button onclick="updateQuantity(${pid}, ${item.quantity - 1})">-</button>
                <span class="item-quantity">${item.quantity}</span>
                <button onclick="updateQuantity(${pid}, ${item.quantity + 1})">+</button>
            </div>
            <span class="item-price">$${(Number(item.price) * item.quantity).toFixed(2)}</span>
            <button class="remove-item" onclick="removeFromCart(${pid})">×</button>
        </li>
    `).join('');

    cartTotal.textContent = `$${total.toFixed(2)}`;
    checkoutBtn.disabled = total === 0;
}

// Update item quantity
async function updateQuantity(productId, newQuantity) {
    if (newQuantity < 1) {
        await removeFromCart(productId);
        return;
    }

    if (cart.items[productId]) {
        cart.items[productId].quantity = newQuantity;
        saveCart();
        await updateCartDisplay();
    }
}

// Remove from cart
async function removeFromCart(productId) {
    delete cart.items[productId];
    saveCart();
    await updateCartDisplay();
}

// Save cart to localStorage
function saveCart() {
    localStorage.setItem('shopping_cart', JSON.stringify(cart));
}

// Load cart from localStorage
async function loadCart() {
    try {
        const savedCart = localStorage.getItem('shopping_cart');
        if (savedCart) {
            cart = JSON.parse(savedCart);
            await updateCartDisplay();
        }
    } catch (error) {
        console.error('Error loading cart:', error);
        cart = { items: {} };
        saveCart();
    }
}

// Show added to cart feedback
function showAddedFeedback() {
    const feedback = document.createElement('div');
    feedback.className = 'add-to-cart-feedback';
    feedback.textContent = 'Added to cart!';
    document.body.appendChild(feedback);

    setTimeout(() => {
        feedback.remove();
    }, 2000);
}