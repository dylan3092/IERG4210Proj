document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOM Content Loaded');
    
    // Fetch categories from API
    try {
        console.log('Fetching categories...');
        const response = await fetch('/api/categories');
        console.log('Categories response:', response);
        const categories = await response.json();
        console.log('Categories data:', categories);
        
        // Update categories list in sidebar
        const categoriesList = document.querySelector('aside ul');
        if (!categoriesList) {
            console.error('Categories list element not found');
            return;
        }
        
        categoriesList.innerHTML = categories.map(category => `
            <li><a href="?category=${category.catid}">${category.name}</a></li>
        `).join('');

    } catch (error) {
        console.error('Error fetching categories:', error);
    }

    // Fetch products
    try {
        console.log('Fetching products...');
        const response = await fetch('/api/products');
        console.log('Products response:', response);
        const products = await response.json();
        console.log('Products data:', products);
        
        // Update product list
        const productList = document.querySelector('.product-list');
        if (!productList) {
            console.error('Product list element not found');
            return;
        }
        
        productList.innerHTML = products.map(product => `
            <article class="product-item">
                <a href="product.html?product=${product.pid}">
                    <img src="${product.image ? '/uploads/' + product.image : '/images/default.jpg'}" 
                         alt="${product.name}" width="150" height="150">
                    <h3>${product.name}</h3>
                </a>
                <p class="price">$${product.price.toFixed(2)}</p>
                <button onclick="addToCart(${product.pid})">Add to Cart</button>
            </article>
        `).join('');

    } catch (error) {
        console.error('Error fetching products:', error);
    }
}); 