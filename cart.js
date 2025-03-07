// 购物车数据结构
let cart = {
    items: [],
    total: 0
};

// 初始化购物车功能
document.addEventListener('DOMContentLoaded', () => {
    // 为所有"Add to Cart"按钮添加点击事件
    const addButtons = document.querySelectorAll('.product-item button');
    addButtons.forEach(button => {
        button.addEventListener('click', addToCart);
    });

    // 从localStorage加载购物车数据（如果有）
    loadCart();
});

// 添加商品到购物车
function addToCart(event) {
    const productItem = event.target.closest('.product-item');
    const productName = productItem.querySelector('h3').textContent;
    const priceText = productItem.querySelector('.price').textContent;
    const price = parseFloat(priceText.replace('$', ''));
    
    // 检查商品是否已在购物车中
    const existingItem = cart.items.find(item => item.name === productName);
    
    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.items.push({
            name: productName,
            price: price,
            quantity: 1
        });
    }
    
    // 更新总价
    updateTotal();
    // 更新购物车显示
    updateCartDisplay();
    // 保存购物车数据
    saveCart();
    
    // 添加动画效果
    showAddedFeedback(event.target);
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
    cartList.innerHTML = '';
    
    cart.items.forEach(item => {
        const li = document.createElement('li');
        li.innerHTML = `
            ${item.name} x ${item.quantity} 
            <span class="item-price">$${(item.price * item.quantity).toFixed(2)}</span>
            <button class="remove-item" onclick="removeItem('${item.name}')">×</button>
        `;
        cartList.appendChild(li);
    });
}

// 从购物车中移除商品
function removeItem(productName) {
    cart.items = cart.items.filter(item => item.name !== productName);
    updateTotal();
    updateCartDisplay();
    saveCart();
}

// 保存购物车数据到localStorage
function saveCart() {
    localStorage.setItem('shoppingCart', JSON.stringify(cart));
}

// 从localStorage加载购物车数据
function loadCart() {
    const savedCart = localStorage.getItem('shoppingCart');
    if (savedCart) {
        cart = JSON.parse(savedCart);
        updateTotal();
        updateCartDisplay();
    }
}

// 添加商品时的视觉反馈
function showAddedFeedback(button) {
    button.textContent = 'Added!';
    button.style.backgroundColor = '#4CAF50';
    
    setTimeout(() => {
        button.textContent = 'Add to Cart';
        button.style.backgroundColor = '';
    }, 1000);
} 