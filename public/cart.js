// 购物车数据结构
let cart = {
    items: [],
    total: 0
};

// 初始化购物车功能
document.addEventListener('DOMContentLoaded', () => {
    // 从localStorage加载购物车数据（如果有）
    loadCart();

    // Add hover functionality to cart
    const cartSection = document.querySelector('.shopping-cart');
    const cartDetails = document.querySelector('.cart-details');

    cartSection.addEventListener('mouseenter', () => {
        cartDetails.style.display = 'block';
    });

    cartSection.addEventListener('mouseleave', () => {
        cartDetails.style.display = 'none';
    });
});

// 添加商品到购物车
async function addToCart(productId, quantity = 1) {
    try {
        // Fetch product details from API
        const response = await fetch(`${BASE_URL}/api/products/${productId}`);
        const product = await response.json();

        quantity = parseInt(quantity);
        if (isNaN(quantity) || quantity < 1) quantity = 1;

        // 检查商品是否已在购物车中
        const existingItem = cart.items.find(item => item.pid === product.pid);
        
        if (existingItem) {
            existingItem.quantity += quantity;
        } else {
            cart.items.push({
                pid: product.pid,
                name: product.name,
                price: Number(product.price),
                quantity: quantity
            });
        }
        
        // 更新总价
        updateTotal();
        // 更新购物车显示
        updateCartDisplay();
        // 保存购物车数据
        saveCart();
        
        // 添加动画效果
        showAddedFeedback();
        
    } catch (error) {
        console.error('Error adding to cart:', error);
    }
}

// 更新购物车总价
function updateTotal() {
    cart.total = cart.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    document.getElementById('cart-total').textContent = `$${cart.total.toFixed(2)}`;
    
    // 更新结账按钮状态
    const checkoutBtn = document.getElementById('checkout-btn');
    checkoutBtn.disabled = cart.total === 0;
}

// 更新购物车显示
function updateCartDisplay() {
    const cartList = document.getElementById('cart-items');
    cartList.innerHTML = cart.items.map(item => `
        <li>
            <span class="item-name">${item.name}</span>
            <div class="item-controls">
                <button onclick="updateQuantity(${item.pid}, ${item.quantity - 1})">-</button>
                <span class="item-quantity">${item.quantity}</span>
                <button onclick="updateQuantity(${item.pid}, ${item.quantity + 1})">+</button>
            </div>
            <span class="item-price">$${(item.price * item.quantity).toFixed(2)}</span>
            <button class="remove-item" onclick="removeFromCart(${item.pid})">×</button>
        </li>
    `).join('');
}

// 更新商品数量
function updateQuantity(productId, newQuantity) {
    if (newQuantity < 1) {
        removeFromCart(productId);
        return;
    }

    const item = cart.items.find(item => item.pid === productId);
    if (item) {
        item.quantity = newQuantity;
        updateTotal();
        updateCartDisplay();
        saveCart();
    }
}

// 从购物车中移除商品
function removeFromCart(productId) {
    cart.items = cart.items.filter(item => item.pid !== productId);
    updateTotal();
    updateCartDisplay();
    saveCart();
}

// 保存购物车数据到localStorage
function saveCart() {
    localStorage.setItem('shopping_cart', JSON.stringify(cart));
}

// 从localStorage加载购物车数据
function loadCart() {
    const savedCart = localStorage.getItem('shopping_cart');
    if (savedCart) {
        cart = JSON.parse(savedCart);
        updateTotal();
        updateCartDisplay();
    }
}

// 添加商品时的视觉反馈
function showAddedFeedback() {
    const feedback = document.createElement('div');
    feedback.className = 'add-to-cart-feedback';
    feedback.textContent = 'Added to cart!';
    document.body.appendChild(feedback);

    setTimeout(() => {
        feedback.remove();
    }, 2000);
} 