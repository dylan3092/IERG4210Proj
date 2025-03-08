// Cart data structure
let cart = {
    items: {} // Using object with pid as key for easier lookup
};

// Initialize cart functionality
document.addEventListener('DOMContentLoaded', async () => {
    // Load cart data from localStorage
    await loadCart();

    // Add hover functionality to cart
    const cartSection = document.querySelector('.shopping-cart');
    const cartDetails = document.querySelector('.cart-details');

    if (cartSection && cartDetails) {
        cartSection.addEventListener('mouseenter', () => {
            cartDetails.style.display = 'block';
        });

        cartSection.addEventListener('mouseleave', () => {
            cartDetails.style.display = 'none';
        });
    }
});

// Add to cart function
async function addToCart(productId, quantity = 1) {
    console.log('Adding to cart:', productId, quantity);
    try {
        quantity = parseInt(quantity);
        if (isNaN(quantity) || quantity < 1) quantity = 1;

        // First, update the quantity in localStorage
        if (!cart.items[productId]) {
            cart.items[productId] = {
                quantity: 0,
            };
        }
        cart.items[productId].quantity += quantity;

        // Save to localStorage immediately
        saveCart();

        // Then fetch latest product details via AJAX
        await updateProductDetails(productId);
        
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
        if (!response.ok) throw new Error('Product not found');
        
        const product = await response.json();
        console.log('Received product details:', product);
        
        // Update cart item with latest product details
        cart.items[productId] = {
            ...cart.items[productId],
            name: product.name,
            price: Number(product.price)
        };
        
        // Save updated details to localStorage
        saveCart();
    } catch (error) {
        console.error('Error fetching product details:', error);
    }
}

// Update cart display
async function updateCartDisplay() {
    const cartList = document.getElementById('cart-items');
    const cartTotal = document.getElementById('cart-total');
    const checkoutBtn = document.getElementById('checkout-btn');
    
    if (!cartList || !cartTotal || !checkoutBtn) return;

    // Ensure all product details are up to date
    await Promise.all(
        Object.keys(cart.items).map(pid => updateProductDetails(pid))
    );

    // Calculate total
    const total = Object.values(cart.items).reduce(
        (sum, item) => sum + (item.price * item.quantity), 
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
            <span class="item-price">$${(item.price * item.quantity).toFixed(2)}</span>
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

// Load cart from localStorage and fetch product details
async function loadCart() {
    const savedCart = localStorage.getItem('shopping_cart');
    if (savedCart) {
        cart = JSON.parse(savedCart);
        // Fetch latest product details for all items
        await updateCartDisplay();
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