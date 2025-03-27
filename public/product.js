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
            <li><a href="/?category=${category.catid}">${category.name}</a></li>
        `).join('');

        // Fetch product details
        const productResponse = await fetch(`${BASE_URL}/api/products/${productId}`);
        if (!productResponse.ok) {
            throw new Error('Product not found');
        }
        
        const product = await productResponse.json();
        
        // Update page title
        document.title = `${product.name} - Dummy Shopping`;

        // Update breadcrumb using category_name from API
        const breadcrumb = document.querySelector('.breadcrumb');
        breadcrumb.innerHTML = `
            <a href="/">Home</a>
            <span class="separator"> > </span>
            <a href="/?category=${product.catid}">${product.category_name}</a>
            <span class="separator"> > </span>
            <span>${product.name}</span>
        `;

        // Display product details
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = `
            <div class="product-image">
                <img src="${product.image ? 
                    `${BASE_URL}/uploads/${product.image}` : 
                    'images/default.jpg'}" 
                    alt="${product.name}">
            </div>
            <div class="product-info">
                <h1>${product.name}</h1>
                <p class="category">Category: ${product.category_name}</p>
                <p class="price">$${Number(product.price).toFixed(2)}</p>
                <p class="description">${product.description}</p>
                <div class="purchase-controls">
                    <input type="number" id="quantity" value="1" min="1" max="99">
                    <button onclick="addToCart(${product.pid}, document.getElementById('quantity').value)">
                        Add to Cart
                    </button>
                </div>
            </div>
        `;

    } catch (error) {
        console.error('Error:', error);
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = '<p class="error">Product not found</p>';
    }
}); 