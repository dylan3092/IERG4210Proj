document.addEventListener('DOMContentLoaded', async () => {
    // Get current category from URL if exists
    const urlParams = new URLSearchParams(window.location.search);
    const currentCategory = urlParams.get('category');
    
    // Fetch categories
    try {
        console.log('Fetching categories...');
        const response = await fetch('http://s15.ierg4210.ie.cuhk.edu.hk:3000/api/categories');
        const categories = await response.json();
        
        const categoriesList = document.querySelector('aside ul');
        categoriesList.innerHTML = categories.map(category => `
            <li>
                <a href="?category=${category.catid}" 
                   class="${currentCategory == category.catid ? 'active' : ''}">
                    ${category.name}
                </a>
            </li>
        `).join('');
        
        // Add "All Products" option
        categoriesList.insertAdjacentHTML('afterbegin', `
            <li>
                <a href="/" class="${!currentCategory ? 'active' : ''}">
                    All Products
                </a>
            </li>
        `);
    } catch (error) {
        console.error('Error fetching categories:', error);
    }

    // Fetch products based on category
    try {
        console.log('Fetching products...');
        const productsUrl = currentCategory 
            ? `http://s15.ierg4210.ie.cuhk.edu.hk:3000/api/products?category=${currentCategory}`
            : 'http://s15.ierg4210.ie.cuhk.edu.hk:3000/api/products';
            
        const response = await fetch(productsUrl);
        const products = await response.json();
        
        const productList = document.querySelector('.product-list');
        
        if (products.length === 0) {
            productList.innerHTML = '<p>No products found in this category.</p>';
            return;
        }
        
        productList.innerHTML = products.map(product => {
            const price = typeof product.price === 'number' ? 
                product.price : Number(product.price);
            
            return `
                <article class="product-item">
                    <a href="product.html?product=${product.pid}">
                        <img src="${product.thumbnail ? 
                            `${BASE_URL}/uploads/${product.thumbnail}` : 
                            'images/default.jpg'}" 
                            alt="${product.name}" width="150" height="150">
                        <h3>${product.name}</h3>
                    </a>
                    <p class="price">$${price.toFixed(2)}</p>
                    <button>Add to Cart</button>
                </article>
            `;
        }).join('');

        // Update page title and breadcrumb based on category
        if (currentCategory) {
            const selectedCategory = categories.find(c => c.catid == currentCategory);
            if (selectedCategory) {
                document.title = `${selectedCategory.name} - Dummy Shopping`;
                updateBreadcrumb(selectedCategory.name);
            }
        }

    } catch (error) {
        console.error('Error fetching products:', error);
        console.error('Error details:', error.stack);
    }
});

// Function to update breadcrumb
function updateBreadcrumb(categoryName) {
    const breadcrumb = document.querySelector('.breadcrumb');
    breadcrumb.innerHTML = `
        <a href="/">Home</a>
        ${categoryName ? `<span class="separator"> > </span><span>${categoryName}</span>` : ''}
    `;
}