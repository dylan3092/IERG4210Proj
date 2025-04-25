// OOP implementation of Shopping Cart
class CartItem {
    constructor(productId, name, price, quantity = 1, image = null) {
        this.productId = productId;
        this.name = name;
        this.price = Number(price);
        this.quantity = quantity;
        this.image = image;
    }

    getTotal() {
        return this.price * this.quantity;
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
                            item.image || null
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
        localStorage.setItem('shopping_cart', JSON.stringify({
            items: this.items
        }));
        this.emit('updated', this);
    }

    // Add item to cart
    async addItem(productId, quantity = 1) {
        if (this.isLoading) return;
        this.isLoading = true;
        
        try {
            // Strict validation - reject invalid inputs
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

            // Fetch product details first to verify it exists
            const productDetails = await this.fetchProductDetails(sanitizedProductId);
            if (!productDetails) {
                throw new Error('Product not found');
            }

            // Preload image
            await this.preloadProductImage(sanitizedProductId);

            // Update cart
            if (this.items[sanitizedProductId]) {
                this.items[sanitizedProductId].updateQuantity(this.items[sanitizedProductId].quantity + quantity);
            } else {
                this.items[sanitizedProductId] = new CartItem(
                    sanitizedProductId,
                    productDetails.name,
                    productDetails.price,
                    quantity,
                    productDetails.image
                );
            }

            // Save and notify
            this.save();
            this.emit('itemAdded', { productId: sanitizedProductId, quantity });
            
        } catch (error) {
            console.error('Error adding to cart:', error);
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
                    img.src = sanitize.url(`${BASE_URL}/uploads/${product.image}`);
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
                throw new Error('Product not found');
            }
            
            const data = await response.json();
            // Sanitize response data
            return {
                pid: sanitize.html(data.pid),
                name: sanitize.html(data.name),
                price: sanitize.number(data.price, 0),
                image: data.image ? sanitize.html(data.image) : null,
                description: sanitize.html(data.description),
                catid: sanitize.html(data.catid),
                category_name: sanitize.html(data.category_name)
            };
            
        } catch (error) {
            console.error('Error fetching product details:', error);
            return null;
        }
    }
}

// Function to update hidden fields in the PayPal form
function updatePaypalFormFields(cartItems) {
    const form = document.getElementById('paypal-cart-form');
    if (!form) {
        console.error("PayPal form 'paypal-cart-form' not found!");
        return;
    }

    const itemContainer = document.getElementById('paypal-items-container');
    if (!itemContainer) {
        console.error("PayPal items container 'paypal-items-container' not found!");
        return;
    }

    // Clear previous items fields
    itemContainer.innerHTML = '';

    // Loop through cart items (expecting CartItem instances)
    Object.values(cartItems).forEach((item, index) => {
        const itemNumber = index + 1; // PayPal item index starts from 1

        // --- Create item_name_X ---
        const nameInput = document.createElement('input');
        nameInput.type = 'hidden';
        nameInput.name = `item_name_${itemNumber}`;
        nameInput.value = item.name; // Assuming item.name exists
        itemContainer.appendChild(nameInput);

        // --- Create item_number_X (using Product ID) ---
        const numberInput = document.createElement('input');
        numberInput.type = 'hidden';
        numberInput.name = `item_number_${itemNumber}`;
        numberInput.value = item.productId; // Assuming item.productId exists
        itemContainer.appendChild(numberInput);

        // --- Create quantity_X ---
        const quantityInput = document.createElement('input');
        quantityInput.type = 'hidden';
        quantityInput.name = `quantity_${itemNumber}`;
        quantityInput.value = item.quantity; // Assuming item.quantity exists
        itemContainer.appendChild(quantityInput);
    });
}

// Cart UI Controller
class CartUIController {
    constructor(cart) {
        this.cart = cart;
        this.cartList = document.getElementById('cart-items');
        this.cartTotal = document.getElementById('cart-total');
        this.checkoutBtn = document.getElementById('checkout-btn');
        
        // Set up event listeners
        this.cart.on('updated', () => this.updateDisplay());
        this.cart.on('itemAdded', () => this.showAddedFeedback());
        
        // Initialize UI
        this.initializeUI();
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
            console.warn('Cart UI elements not found. Skipping update.');
            return;
        }
        
        this.cartList.innerHTML = ''; // Clear existing items
        const items = Object.values(this.cart.items);
        
        if (items.length === 0) {
            this.cartList.innerHTML = '<li>Your cart is empty.</li>';
            this.checkoutBtn.disabled = true;
        } else {
            items.forEach(item => {
                const li = document.createElement('li');
                li.dataset.pid = item.productId;
                
                // Sanitize all dynamic content before adding to DOM
                const safeName = sanitize.html(item.name);
                const safePrice = sanitize.number(item.price, 2).toFixed(2);
                const safeTotal = sanitize.number(item.getTotal(), 2).toFixed(2);
                const safeQuantity = sanitize.number(item.quantity);
                
                // Use textContent for safe text insertion
                li.innerHTML = `
                    ${safeName} - 
                    $${safePrice} x 
                    <input type="number" class="quantity-input" value="${safeQuantity}" min="1" max="100" data-pid="${item.productId}"> = 
                    $${safeTotal}
                    <button class="remove-item" data-pid="${item.productId}">Remove</button>
                `;
                this.cartList.appendChild(li);
            });
            this.checkoutBtn.disabled = false;
        }
        
        // Update total (animate)
        const currentTotal = parseFloat(this.cartTotal.textContent.replace(/[^\d.]/g, '')) || 0;
        const newTotal = this.cart.getTotal();
        this.animateValue(this.cartTotal, currentTotal, newTotal, 300);
        
        // ** Add call to update PayPal hidden fields **
        updatePaypalFormFields(this.cart.items);
        
        // Add event listeners to new quantity inputs and remove buttons
        this.cartList.querySelectorAll('.quantity-input').forEach(input => {
            input.addEventListener('change', () => {
                const productId = input.getAttribute('data-pid');
                const newQuantity = parseInt(input.value);
                this.updateQuantity(productId, newQuantity);
            });
        });
        
        this.cartList.querySelectorAll('.remove-item').forEach(button => {
            button.addEventListener('click', () => {
                const productId = button.getAttribute('data-pid');
                this.removeItem(productId);
            });
        });
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
}

// Create global instances
const cart = new ShoppingCart();
const cartController = new CartUIController(cart);

// Public API for use in HTML
function addToCart(productId, quantity = 1) {
    const sanitizedProductId = sanitize.html(productId);
    cart.addItem(sanitizedProductId, sanitize.number(quantity, 1));
}

function updateQuantity(productId, newQuantity) {
    const sanitizedProductId = sanitize.html(productId);
    cartController.updateQuantity(sanitizedProductId, sanitize.number(newQuantity, 1));
}

function removeFromCart(productId) {
    const sanitizedProductId = sanitize.html(productId);
    cartController.removeItem(sanitizedProductId);
}

// Initialize cart functionality
document.addEventListener('DOMContentLoaded', async () => {
    await cart.load();
});

// Load cart data
cart.load();

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