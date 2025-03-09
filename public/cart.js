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
                const parsedCart = JSON.parse(savedCart);
                
                // Convert plain objects to CartItem instances
                Object.entries(parsedCart.items).forEach(([pid, item]) => {
                    this.items[pid] = new CartItem(
                        pid, 
                        item.name, 
                        item.price, 
                        item.quantity, 
                        item.image
                    );
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
            quantity = parseInt(quantity);
            if (isNaN(quantity) || quantity < 1) quantity = 1;

            // Fetch product details first to verify it exists
            const productDetails = await this.fetchProductDetails(productId);
            if (!productDetails) {
                throw new Error('Product not found');
            }

            // Preload image
            await this.preloadProductImage(productId);

            // Update cart
            if (this.items[productId]) {
                this.items[productId].updateQuantity(this.items[productId].quantity + quantity);
            } else {
                this.items[productId] = new CartItem(
                    productId,
                    productDetails.name,
                    productDetails.price,
                    quantity,
                    productDetails.image
                );
            }

            // Save and notify
            this.save();
            this.emit('itemAdded', { productId, quantity });
            
        } catch (error) {
            console.error('Error adding to cart:', error);
        } finally {
            this.isLoading = false;
        }
    }

    // Update item quantity
    updateQuantity(productId, newQuantity) {
        if (newQuantity < 1) {
            this.removeItem(productId);
            return;
        }

        if (this.items[productId]) {
            this.items[productId].updateQuantity(newQuantity);
            this.save();
        }
    }

    // Remove item from cart
    removeItem(productId) {
        if (this.items[productId]) {
            delete this.items[productId];
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
        if (!this.imageCache.has(productId) && this.items[productId]) {
            try {
                const product = await this.fetchProductDetails(productId);
                if (product && product.image) {
                    const img = new Image();
                    img.src = `${BASE_URL}/uploads/${product.image}`;
                    this.imageCache.set(productId, img);
                }
            } catch (error) {
                console.error('Error preloading image:', error);
            }
        }
    }

    // Fetch product details via AJAX
    async fetchProductDetails(productId) {
        try {
            const response = await fetch(`${BASE_URL}/api/products/${productId}`);
            if (!response.ok) {
                throw new Error('Product not found');
            }
            
            return await response.json();
            
        } catch (error) {
            console.error('Error fetching product details:', error);
            return null;
        }
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
        if (!this.cartList || !this.cartTotal || !this.checkoutBtn) return;

        // Calculate total
        const total = this.cart.getTotal();

        // Prepare new content with cached images
        const newContent = Object.entries(this.cart.items).map(([pid, item]) => `
            <li class="cart-item" data-pid="${pid}">
                <div class="item-image">
                    ${this.cart.imageCache.has(pid) ? 
                        `<img src="${this.cart.imageCache.get(pid).src}" alt="${item.name}" width="50">` : 
                        ''}
                </div>
                <span class="item-name">${item.name}</span>
                <div class="item-controls">
                    <button class="quantity-btn" onclick="cartController.updateQuantity('${pid}', ${item.quantity - 1})">-</button>
                    <span class="item-quantity">${item.quantity}</span>
                    <button class="quantity-btn" onclick="cartController.updateQuantity('${pid}', ${item.quantity + 1})">+</button>
                </div>
                <span class="item-price">$${item.getTotal().toFixed(2)}</span>
                <button class="remove-item" onclick="cartController.removeItem('${pid}')">×</button>
            </li>
        `).join('');

        // Smooth transition for total
        const currentTotal = parseFloat(this.cartTotal.textContent.replace('$', ''));
        if (currentTotal !== total) {
            this.animateValue(this.cartTotal, currentTotal, total, 300);
        }

        // Update cart items with transition
        if (this.cartList.innerHTML !== newContent) {
            this.cartList.style.opacity = '0';
            setTimeout(() => {
                this.cartList.innerHTML = newContent;
                this.cartList.style.opacity = '1';
            }, 150);
        }

        this.checkoutBtn.disabled = total === 0;
    }

    // Animate number changes
    animateValue(element, start, end, duration) {
        const startTime = performance.now();
        
        const update = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const current = start + (end - start) * progress;
            element.textContent = `$${current.toFixed(2)}`;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        };

        requestAnimationFrame(update);
    }

    // Show added to cart feedback
    showAddedFeedback() {
        const feedback = document.createElement('div');
        feedback.className = 'add-to-cart-feedback';
        feedback.textContent = 'Added to cart!';
        document.body.appendChild(feedback);
        
        // Remove the feedback after animation completes
        setTimeout(() => {
            feedback.style.opacity = '0';
            feedback.style.transform = 'translateY(-20px) translateX(-50%)';
            feedback.style.transition = 'opacity 0.3s, transform 0.3s';
            
            setTimeout(() => {
                feedback.remove();
            }, 300);
        }, 2000);
    }

    // Add this method to handle item removal
    removeItem(productId) {
        if (this.cart.items[productId]) {
            this.cart.removeItem(productId);
        }
    }
}

// Create global instances
const cart = new ShoppingCart();
const cartController = new CartUIController(cart);

// Public API for use in HTML
function addToCart(productId, quantity = 1) {
    cart.addItem(productId, quantity);
}

function updateQuantity(productId, newQuantity) {
    cartController.updateQuantity(productId, newQuantity);
}

function removeFromCart(productId) {
    cartController.removeItem(productId);
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
  this.cart.updateQuantity(productId, newQuantity);
  this.updateDisplay();
};

CartUIController.prototype.removeItem = function(productId) {
  this.cart.removeItem(productId);
  this.updateDisplay();
};