// Cart data structure with state management
let cart = {
    items: {},
    isLoading: false,
    imageCache: new Map()
};

// Initialize cart functionality
document.addEventListener('DOMContentLoaded', async () => {
    // Load cart data immediately before showing UI
    await loadCart();
    
    // Initialize cart UI only after data is loaded
    initializeCartUI();
    await updateCartDisplay();

    // Preload images for items in cart
    Object.keys(cart.items).forEach(pid => {
        preloadProductImage(pid);
    });
});

// Preload product images
async function preloadProductImage(productId) {
    if (!cart.imageCache.has(productId)) {
        try {
            const product = await updateProductDetails(productId);
            if (product && product.image) {
                const img = new Image();
                img.src = `${BASE_URL}/uploads/${product.image}`;
                cart.imageCache.set(productId, img);
            }
        } catch (error) {
            console.error('Error preloading image:', error);
        }
    }
}

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
    if (cart.isLoading) return;
    cart.isLoading = true;
    
    try {
        quantity = parseInt(quantity);
        if (isNaN(quantity) || quantity < 1) quantity = 1;

        // Fetch product details first to verify it exists
        const productDetails = await updateProductDetails(productId);
        if (!productDetails) {
            throw new Error('Product not found');
        }

        // Preload image
        await preloadProductImage(productId);

        // Optimistic UI update
        const previousState = { ...cart.items };
        if (cart.items[productId]) {
            cart.items[productId].quantity += quantity;
        } else {
            cart.items[productId] = {
                quantity: quantity,
                name: productDetails.name,
                price: Number(productDetails.price),
                image: productDetails.image
            };
        }

        // Update display immediately
        await updateCartDisplay();
        
        // Save to localStorage
        saveCart();
        
        // Show feedback
        showAddedFeedback();
        
    } catch (error) {
        console.error('Error adding to cart:', error);
        // Rollback on error
        cart.items = previousState;
        await updateCartDisplay();
    } finally {
        cart.isLoading = false;
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

// Update cart display with smooth transitions
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

    // Prepare new content with cached images
    const newContent = Object.entries(cart.items).map(([pid, item]) => `
        <li class="cart-item" data-pid="${pid}">
            <div class="item-image">
                ${cart.imageCache.has(pid) ? 
                    `<img src="${cart.imageCache.get(pid).src}" alt="${item.name}" width="50">` : 
                    ''}
            </div>
            <span class="item-name">${item.name}</span>
            <div class="item-controls">
                <button class="quantity-btn" onclick="updateQuantity(${pid}, ${item.quantity - 1})">-</button>
                <span class="item-quantity">${item.quantity}</span>
                <button class="quantity-btn" onclick="updateQuantity(${pid}, ${item.quantity + 1})">+</button>
            </div>
            <span class="item-price">$${(Number(item.price) * item.quantity).toFixed(2)}</span>
            <button class="remove-item" onclick="removeFromCart(${pid})">×</button>
        </li>
    `).join('');

    // Smooth transition for total
    const currentTotal = parseFloat(cartTotal.textContent.replace('$', ''));
    if (currentTotal !== total) {
        animateValue(cartTotal, currentTotal, total, 300);
    }

    // Update cart items with transition
    if (cartList.innerHTML !== newContent) {
        cartList.style.opacity = '0';
        setTimeout(() => {
            cartList.innerHTML = newContent;
            cartList.style.opacity = '1';
        }, 150);
    }

    checkoutBtn.disabled = total === 0;
}

// Animate number changes
function animateValue(element, start, end, duration) {
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        const current = start + (end - start) * progress;
        element.textContent = `$${current.toFixed(2)}`;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
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
        cart = { items: {}, isLoading: false, imageCache: new Map() };
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