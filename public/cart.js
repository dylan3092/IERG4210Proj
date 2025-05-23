// Initialize Stripe (Replace with your actual publishable key)
// IMPORTANT: Make sure Stripe.js script is included in your HTML before this script.
const stripe = Stripe('pk_test_51RJCbCGfdrXt5LBwGqH6Hot5HdIrIQOHEs0EpGKoHEcf7EMG9QVJXzPoarHjzjNJhkV6eGDUbnQhhRG6ar0AU8Oc00ToxczFqW'); 

// OOP implementation of Shopping Cart
class CartItem {
    constructor(productId, name, price, quantity = 1, image = null, discountInfo = null) {
        this.productId = productId;
        this.name = name;
        this.price = Number(price);
        this.quantity = quantity;
        this.image = image;
        this.originalTotal = null;
        this.discountApplied = false;

        this.discountType = null;
        this.bogoBuyQty = null;
        this.bogoGetFreeQty = null;

        if (discountInfo && discountInfo.type === 'BOGO' && 
            Number.isInteger(discountInfo.bogo_buy_quantity) && discountInfo.bogo_buy_quantity > 0 &&
            Number.isInteger(discountInfo.bogo_get_free_quantity) && discountInfo.bogo_get_free_quantity > 0) {
            this.discountType = 'BOGO';
            this.bogoBuyQty = discountInfo.bogo_buy_quantity;
            this.bogoGetFreeQty = discountInfo.bogo_get_free_quantity;
            console.log(`[CartItem ${this.productId}] Initialized with BOGO discount: Buy ${this.bogoBuyQty} Get ${this.bogoGetFreeQty}`);
        }
    }

    getTotal() {
        const rawTotal = this.price * this.quantity;
        this.originalTotal = rawTotal; // Always store the raw total
        this.discountApplied = false;

        // --- GENERALIZED BOGO Discount Logic ---
        if (this.discountType === 'BOGO' && this.bogoBuyQty && this.bogoGetFreeQty) {
            const itemsPerDealCycle = this.bogoBuyQty + this.bogoGetFreeQty;

            if (this.quantity >= itemsPerDealCycle) {
                const numDealCycles = Math.floor(this.quantity / itemsPerDealCycle);
                const numFreeItems = numDealCycles * this.bogoGetFreeQty;
                const numPaidItems = this.quantity - numFreeItems;
                this.discountApplied = true;
                const discountedTotal = numPaidItems * this.price;
                return discountedTotal;
            }
        }
        // --- END: BOGO Discount Logic ---
        
        return rawTotal;
    }

    updateQuantity(newQuantity) {
        this.quantity = Math.max(1, newQuantity);
    }
}

class ShoppingCart {
    constructor() {
        this.items = {};
        this.isLoading = false;
        this.imageCache = new Map();
        this.eventListeners = {};
    }

    // Event handling methods
    on(event, callback) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(callback);
    }

    emit(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => callback(data));
        }
    }

    // Load cart from localStorage
    async load() {
        try {
            const savedCart = localStorage.getItem('shopping_cart');
            if (savedCart) {
                // Sanitize JSON before parsing
                const parsedCart = sanitize.json(savedCart);
                
                // Convert plain objects to CartItem instances
                Object.entries(parsedCart.items || {}).forEach(([pid, item]) => {
                    if (item && typeof item === 'object') {
                        this.items[pid] = new CartItem(
                            pid, 
                            item.name || '', 
                            item.price || 0, 
                            item.quantity || 1, 
                            item.image || null,
                            item.discount || null
                        );
                    }
                });
                
                // Preload images for items in cart
                Object.keys(this.items).forEach(pid => {
                    this.preloadProductImage(pid);
                });
                
                this.emit('updated', this);
            }
        } catch (error) {
            console.error('Error loading cart:', error);
            this.items = {};
            this.save();
        }
    }

    // Save cart to localStorage
    save() {
        console.log("[Cart.save] Saving cart to localStorage:", this.items); // Log save
        localStorage.setItem('shopping_cart', JSON.stringify({
            items: this.items
        }));
        this.emit('updated', this);
        console.log("[Cart.save] Emitted 'updated' event."); // Log emit
    }

    // Add item to cart
    async addItem(productId, quantity = 1) {
        console.log(`[Cart.addItem] Start. ProductId: ${productId}, Quantity: ${quantity}, isLoading: ${this.isLoading}`);
        if (this.isLoading) return;
        this.isLoading = true;
        
        try {
            const sanitizedProductId = sanitize.html(productId);
            
            if (!/^\d+$/.test(quantity.toString())) {
                console.error('Invalid quantity format');
                this.isLoading = false;
                return;
            }
            
            quantity = parseInt(quantity);
            if (isNaN(quantity) || quantity < 1 || quantity > 100) {
                console.error('Invalid quantity value');
                this.isLoading = false;
                return;
            }

            let productDetails = this.items[sanitizedProductId] ? 
                { name: this.items[sanitizedProductId].name, price: this.items[sanitizedProductId].price, image: this.items[sanitizedProductId].image, discount: null } : // Basic info if already in cart
                await this.fetchProductDetails(sanitizedProductId); // Fetch full details if new
            
            if (!productDetails) {
                throw new Error('Product not found or details could not be fetched.');
            }

            // Preload image (already done by fetchProductDetails if it was called, but good to ensure)
            // await this.preloadProductImage(sanitizedProductId, productDetails.image); // preloadProductImage may need productDetails.image

            if (this.items[sanitizedProductId]) {
                this.items[sanitizedProductId].updateQuantity(this.items[sanitizedProductId].quantity + quantity);
            } else {
                // Pass productDetails.discount to CartItem constructor
                this.items[sanitizedProductId] = new CartItem(
                    sanitizedProductId,
                    productDetails.name,
                    productDetails.price,
                    quantity,
                    productDetails.image,
                    productDetails.discount // Pass the whole discount object
                );
            }

            this.save();
            this.emit('itemAdded', { productId: sanitizedProductId, quantity });
            
        } catch (error) {
            console.error('[Cart.addItem] Error adding to cart:', error);
        } finally {
            this.isLoading = false;
        }
    }

    // Update item quantity
    updateQuantity(productId, newQuantity) {
        const sanitizedProductId = sanitize.html(productId);
        newQuantity = sanitize.number(newQuantity, 0);
        
        if (newQuantity < 1) {
            this.removeItem(sanitizedProductId);
            return;
        }

        if (this.items[sanitizedProductId]) {
            this.items[sanitizedProductId].updateQuantity(newQuantity);
            this.save();
        }
    }

    // Remove item from cart
    removeItem(productId) {
        const sanitizedProductId = sanitize.html(productId);
        
        if (this.items[sanitizedProductId]) {
            delete this.items[sanitizedProductId];
            this.save();
        }
    }

    // Get cart total
    getTotal() {
        return Object.values(this.items).reduce(
            (sum, item) => sum + item.getTotal(), 
            0
        );
    }

    // Get item count
    getItemCount() {
        return Object.values(this.items).reduce(
            (count, item) => count + item.quantity, 
            0
        );
    }

    // Preload product images
    async preloadProductImage(productId) {
        const sanitizedProductId = sanitize.html(productId);
        
        if (!this.imageCache.has(sanitizedProductId) && this.items[sanitizedProductId]) {
            try {
                const product = await this.fetchProductDetails(sanitizedProductId);
                if (product && product.image) {
                    const img = new Image();
                    img.src = sanitize.url(`/uploads/${product.image}`);
                    this.imageCache.set(sanitizedProductId, img);
                }
            } catch (error) {
                console.error('Error preloading image:', error);
            }
        }
    }

    // Fetch product details via AJAX
    async fetchProductDetails(productId) {
        try {
            const sanitizedProductId = encodeURIComponent(sanitize.html(productId));
            const response = await fetch(`${BASE_URL}/api/products/${sanitizedProductId}`);
            if (!response.ok) {
                throw new Error(`Product not found (status: ${response.status})`);
            }
            
            const data = await response.json();
            // Sanitize response data but preserve the discount object structure
            return {
                pid: sanitize.html(data.pid),
                name: sanitize.html(data.name),
                price: sanitize.number(data.price, 0),
                image: data.image ? sanitize.html(data.image) : null,
                description: sanitize.html(data.description),
                catid: sanitize.html(data.catid),
                category_name: sanitize.html(data.category_name),
                discount: data.discount // Keep the discount object as is from API
            };
            
        } catch (error) {
            console.error('Error fetching product details:', error);
            return null;
        }
    }

    // Clear the cart (both in memory and localStorage)
    clear() {
        this.items = {};
        this.save(); // Save the empty cart state
        this.emit('cleared'); // Emit an event if needed
        this.emit('updated', this); // Ensure UI updates
    }
}

// Cart UI Controller
class CartUIController {
    constructor(cart) {
        this.cart = cart;
        this.cartList = document.getElementById('cart-items');
        this.cartTotal = document.getElementById('cart-total');
        this.checkoutBtn = document.getElementById('checkout-btn');
        
        // Set up event listeners
        this.cart.on('updated', () => {
             console.log("[CartUIController] Received 'updated' event from cart."); // Log event received
             this.updateDisplay();
        });
        this.cart.on('itemAdded', () => this.showAddedFeedback());
        
        // Initialize UI
        this.initializeUI();
        
        // Add event listener for the checkout button
        if (this.checkoutBtn) {
            this.checkoutBtn.addEventListener('click', () => this.handleCheckout());
        } else {
            console.error("Checkout button (#checkout-btn) not found!");
        }
    }

    initializeUI() {
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

    updateDisplay() {
        if (!this.cartList || !this.cartTotal || !this.checkoutBtn) {
            return;
        }

        Array.from(this.cartList.children).forEach(child => {
            if (!child.classList.contains('removing')) {
                child.remove();
            }
        });

        const items = Object.values(this.cart.items);
        if (items.length === 0) {
            this.cartList.innerHTML = '<li class="empty-cart-message">Your cart is empty.</li>';
            this.checkoutBtn.disabled = true;
        } else {
            items.forEach(item => {
                const li = document.createElement('li');
                li.className = 'cart-item';
                li.dataset.productId = item.productId;

                // DEBUG: Log item image details
                console.log(`[CartUI] Item: ${item.name}, Image Filename: ${item.image}, Full Image URL Attempt: ${item.image ? sanitize.url(`/uploads/${item.image}`) : 'No image'}`);

                const itemImageHTML = item.image ? 
                    `<div class="item-image"><img src="${sanitize.url(`/uploads/${item.image}`)}" alt="${sanitize.attribute(item.name)}"></div>` : 
                    '<div class="item-image placeholder"></div>';
                
                let priceDisplayHTML;
                const currentItemTotal = item.getTotal(); 

                if (item.discountApplied && item.originalTotal != null && item.originalTotal > currentItemTotal) {
                    priceDisplayHTML = `
                        <span class="original-price"><s>$${sanitize.html(item.originalTotal.toFixed(2))}</s></span> 
                        <span class="discounted-price">$${sanitize.html(currentItemTotal.toFixed(2))}</span>
                    `;
                } else {
                    // Display the raw total if no discount or if discounted total isn't less (e.g. bad rule)
                    priceDisplayHTML = `$${sanitize.html(item.originalTotal != null ? item.originalTotal.toFixed(2) : currentItemTotal.toFixed(2))}`;
                }

                // Corrected item name display and quantity input
                li.innerHTML = `
                    ${itemImageHTML}
                    <div class="item-info">
                        <span class="item-name">${sanitize.html(item.name)}</span>
                        <div class="item-controls">
                            <button class="quantity-btn decrease-qty" data-product-id="${item.productId}" ${item.quantity <= 1 ? 'disabled' : ''}>-</button>
                            <input type="number" class="item-quantity-input" value="${sanitize.html(item.quantity)}" min="1" max="100" data-product-id="${item.productId}">
                            <button class="quantity-btn increase-qty" data-product-id="${item.productId}">+</button>
                        </div>
                    </div>
                    <span class="item-price">${priceDisplayHTML}</span> 
                    <button class="remove-item" data-product-id="${item.productId}">&times;</button>
                `;
                this.cartList.appendChild(li);

                // --- NEW: Add event listeners to the new elements directly --- 
                li.querySelector('.decrease-qty').addEventListener('click', (e) => {
                    const pid = e.target.dataset.productId;
                    this.updateQuantity(pid, this.cart.items[pid].quantity - 1);
                });
                li.querySelector('.increase-qty').addEventListener('click', (e) => {
                    const pid = e.target.dataset.productId;
                    this.updateQuantity(pid, this.cart.items[pid].quantity + 1);
                });
                li.querySelector('.item-quantity-input').addEventListener('change', (e) => {
                    const pid = e.target.dataset.productId;
                    let newQuantity = parseInt(e.target.value, 10);
                    if (isNaN(newQuantity) || newQuantity < 1) newQuantity = 1;
                    if (newQuantity > 100) newQuantity = 100;
                    e.target.value = newQuantity; // Reflect sanitized value
                    this.updateQuantity(pid, newQuantity);
                });
                li.querySelector('.remove-item').addEventListener('click', (e) => {
                    const pid = e.target.dataset.productId;
                    this.removeItem(pid);
                });
                // --- END: New event listeners ---
            });
            this.checkoutBtn.disabled = false;
        }

        const newTotal = this.cart.getTotal();
        this.animateValue(this.cartTotal, parseFloat(this.cartTotal.textContent.replace(/[^\d.]/g, '')) || 0, newTotal, 300);
    }

    // Animate number changes
    animateValue(element, start, end, duration) {
        const startTime = performance.now();
        
        const update = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const current = start + (end - start) * progress;
            element.textContent = `$${sanitize.html(current.toFixed(2))}`;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        };

        requestAnimationFrame(update);
    }

    // Show added to cart feedback
    showAddedFeedback() {
        // Remove any existing notifications first
        const existingNotifications = document.querySelectorAll('.notification');
        existingNotifications.forEach(node => node.remove());
        
        // Create new notification
        const feedback = document.createElement('div');
        feedback.className = 'notification';
        feedback.textContent = 'Added to cart!';
        feedback.style.backgroundColor = '#4CAF50'; // Ensure green background
        document.body.appendChild(feedback);
        
        // Remove the feedback after animation completes
        setTimeout(() => {
            feedback.style.opacity = '0';
            feedback.style.transform = 'translateX(-100%)';
            feedback.style.transition = 'opacity 0.3s, transform 0.3s';
            
            setTimeout(() => {
                feedback.remove();
            }, 300);
        }, 2000);
    }

    // Add this method to handle item removal
    removeItem(productId) {
        const sanitizedProductId = sanitize.html(productId);
        if (this.cart.items[sanitizedProductId]) {
            this.cart.removeItem(sanitizedProductId);
        }
    }

    // Add this method to handle Stripe Checkout
    async handleCheckout() {
        console.log("[CartUIController.handleCheckout] Checkout button clicked.");
        this.checkoutBtn.disabled = true; // Disable button during processing
        this.checkoutBtn.textContent = 'Processing...';

        // 1. Get cart items from the cart object
        const cartItemsForApi = Object.values(this.cart.items).map(item => ({
            pid: item.productId,
            quantity: item.quantity
        }));

        if (cartItemsForApi.length === 0) {
            alert('Your cart is empty.');
            this.checkoutBtn.disabled = false;
            this.checkoutBtn.textContent = 'Checkout';
            return;
        }

        const cartData = {
            items: cartItemsForApi
        };

        try {
            // 2. Call backend to create the Stripe Checkout session
            console.log("[CartUIController.handleCheckout] Sending request to /api/create-checkout-session with data:", cartData);
            const response = await fetch(`${BASE_URL}/api/create-checkout-session`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': sessionStorage.getItem('csrfToken')
                },
                body: JSON.stringify(cartData),
            });

            console.log("[CartUIController.handleCheckout] Received response status:", response.status);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: response.statusText })); // Handle non-JSON errors
                console.error('[CartUIController.handleCheckout] Failed to create checkout session:', errorData.error);
                alert(`Error preparing checkout: ${errorData.error || 'Please try again.'}`);
                this.checkoutBtn.disabled = false;
                this.checkoutBtn.textContent = 'Checkout';
                return;
            }

            const { sessionId } = await response.json();
            console.log("[CartUIController.handleCheckout] Received Stripe session ID:", sessionId);

            // 3. Redirect to Stripe Checkout
            console.log("[CartUIController.handleCheckout] Redirecting to Stripe Checkout...");
            const { error } = await stripe.redirectToCheckout({
                sessionId: sessionId
            });

            // If redirectToCheckout fails (e.g., network error, user cancels), display error
            if (error) {
                console.error('[CartUIController.handleCheckout] Stripe redirectToCheckout error:', error);
                alert(error.message);
                this.checkoutBtn.disabled = false; // Re-enable button on client-side errors
                this.checkoutBtn.textContent = 'Checkout';
            }
            // If redirect is successful, the user leaves this page.
            // Consider clearing the cart here OR on the success page.
            // this.cart.clear(); 

        } catch (error) {
            console.error('[CartUIController.handleCheckout] Checkout error:', error);
            alert('An unexpected error occurred during checkout. Please check the console.');
            this.checkoutBtn.disabled = false; // Re-enable button on unexpected errors
            this.checkoutBtn.textContent = 'Checkout';
        }
    }
}

// Create global instances
const cart = new ShoppingCart();
const cartController = new CartUIController(cart);

// Public API for use in HTML
window.addToCart = function(productId, quantity = 1) {
    console.log(`[addToCart] Called with productId: ${productId}, quantity: ${quantity}`); // Log entry
    const sanitizedProductId = sanitize.html(productId);
    console.log(`[addToCart] Sanitized productId: ${sanitizedProductId}`); // Log sanitized ID
    cart.addItem(sanitizedProductId, sanitize.number(quantity, 1));
}

window.updateQuantity = function(productId, newQuantity) {
    const sanitizedProductId = sanitize.html(productId);
    cartController.updateQuantity(sanitizedProductId, sanitize.number(newQuantity, 1));
}

window.removeFromCart = function(productId) {
    const sanitizedProductId = sanitize.html(productId);
    cartController.removeItem(sanitizedProductId);
}

// Initialize cart functionality
document.addEventListener('DOMContentLoaded', async () => {
    await cart.load();

    // Add Checkout Button Event Listener
    const checkoutButton = document.getElementById('checkout-btn');
    // REMOVE PayPal element checks:
    // const paypalForm = document.getElementById('paypal-cart-form'); 
    // const invoiceInput = document.getElementById('paypal-invoice');
    // const customInput = document.getElementById('paypal-custom');

    // Modify condition to only check for the essential button
    if (checkoutButton /* && other essential elements if any */) { 
        // The actual event listener logic might be attached elsewhere or handled by CartUIController
        // This block might just need to confirm the button exists, or could potentially be removed
        // if the listener is guaranteed to be attached correctly by other means.
        console.log('Checkout button (#checkout-btn) found. Listener should be attached elsewhere or is handled by CartUIController.');
        
        // If the checkout logic WAS here (like the PayPal logic was), ensure the correct 
        // Stripe checkout logic (e.g., calling cartController.handleCheckout()) is triggered.
        // Example (IF NEEDED - check if handleCheckout is called elsewhere first):
        /*
        checkoutButton.addEventListener('click', async () => {
            await cartController.handleCheckout(); 
        });
        */

    } else {
        // This error should now only trigger if the #checkout-btn itself is missing
        console.error('Checkout button (#checkout-btn) not found!');
    }
});

// Expose cart controller to window for button click handlers
window.cartController = cartController;

// Add these methods to CartUIController class
CartUIController.prototype.updateQuantity = function(productId, newQuantity) {
  const sanitizedProductId = sanitize.html(productId);
  this.cart.updateQuantity(sanitizedProductId, sanitize.number(newQuantity, 1));
  this.updateDisplay();
};

CartUIController.prototype.removeItem = function(productId) {
  const sanitizedProductId = sanitize.html(productId);
  this.cart.removeItem(sanitizedProductId);
  this.updateDisplay();
};