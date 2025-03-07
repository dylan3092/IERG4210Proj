document.addEventListener('DOMContentLoaded', async () => {
    // Fetch categories from API
    try {
        const response = await fetch('/api/categories');
        const categories = await response.json();
        
        // Update categories list in sidebar
        const categoriesList = document.querySelector('aside ul');
        categoriesList.innerHTML = categories.map(category => `
            <li><a href="?category=${category.catid}">${category.name}</a></li>
        `).join('');

    } catch (error) {
        console.error('Error fetching categories:', error);
    }

    // Fetch products (you can add category filtering later)
    try {
        const response = await fetch('/api/products');
        const products = await response.json();
        
        // Update product list
        const productList = document.querySelector('.product-list');
        productList.innerHTML = products.map(product => `
            <article class="product-item">
                <a href="product.html?product=${product.pid}">
                    <img src="${product.image ? 'uploads/' + product.image : 'images/default.jpg'}" 
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