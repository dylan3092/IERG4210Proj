// Global state for categories
let categoriesCache = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize router with a more specific selector
    router.init('main');
    
    // Register routes
    router.register('/', homeHandler);
    router.register('/index.html', homeHandler);
    router.register('/product.html', productHandler);
    router.register('404', notFoundHandler);
    router.register('error', errorHandler);
    
    // Load categories (shared across all pages)
    await loadCategories();
    
    // Listen for route changes to update categories
    router.on('routeChanged', () => {
        renderCategories();
    });
    
    // Check if we need to initialize the page structure
    const currentPath = window.location.pathname + window.location.search;
    initializePageStructure(currentPath);
    
    router.handleRouteChange(currentPath);
});

// Load categories once and cache them
async function loadCategories() {
    try {
        const response = await fetch(`${BASE_URL}/api/categories`);
        categoriesCache = await response.json();
        
        // Render categories in sidebar
        renderCategories();
        
        return categoriesCache;
    } catch (error) {
        console.error('Error fetching categories:', error);
        return [];
    }
}

// Render categories in sidebar
function renderCategories() {
    const categoryLists = document.querySelectorAll('aside ul');
    if (!categoryLists.length) return; // No category lists found
    
    // Get current category from URL
    const urlParams = new URLSearchParams(window.location.search);
    const currentCategoryId = urlParams.get('category');
    
    // Update all category lists
    categoryLists.forEach(categoryList => {
        // Start with "All Products" option
        let categoriesHTML = `
            <li>
                <a href="/" class="${!currentCategoryId ? 'active' : ''}">
                    All Products
                </a>
            </li>
        `;
        
        // Add the rest of the categories
        categoriesHTML += categoriesCache.map(category => {
            const isActive = currentCategoryId == category.catid;
            return `
                <li>
                    <a href="/?category=${category.catid}" 
                       class="${isActive ? 'active' : ''}">
                        ${category.name}
                    </a>
                </li>
            `;
        }).join('');
        
        categoryList.innerHTML = categoriesHTML;
    });
}

// Home page handler
async function homeHandler(params) {
    // Get category from params
    const categoryId = params.category;
    
    try {
        // Fetch products based on category
        const productsUrl = categoryId 
            ? `${BASE_URL}/api/products?category=${categoryId}`
            : `${BASE_URL}/api/products`;
            
        const response = await fetch(productsUrl);
        const products = await response.json();
        
        // Update page title and breadcrumb based on category
        if (categoryId) {
            const selectedCategory = categoriesCache.find(c => c.catid == categoryId);
            if (selectedCategory) {
                document.title = `${selectedCategory.name} - Dummy Shopping`;
                updateBreadcrumb(selectedCategory.name);
            }
        } else {
            document.title = 'Dummy Shopping - Home';
            updateBreadcrumb();
        }
        
        // Highlight active category
        renderCategories();
        
        // Return HTML for products only
        if (products.length === 0) {
            return '<p>No products found in this category.</p>';
        }
        
        return products.map(product => {
            const price = typeof product.price === 'number' ? 
                product.price : Number(product.price);
            
            return `
                <article class="product-item">
                    <a href="/product.html?product=${product.pid}">
                        <img src="${product.thumbnail ? 
                            `${BASE_URL}/uploads/${product.thumbnail}` : 
                            'images/default.jpg'}" 
                            alt="${product.name}" width="150" height="150">
                        <h3>${product.name}</h3>
                    </a>
                    <p class="price">$${price.toFixed(2)}</p>
                    <button type="button" onclick="addToCart(${product.pid}, 1)">Add to Cart</button>
                </article>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error fetching products:', error);
        return '<p>Error loading products. Please try again later.</p>';
    }
}

// Product page handler
async function productHandler(params) {
    // Get product ID from params
    const productId = params.product;
    
    if (!productId) {
        router.navigate('/');
        return '';
    }
    
    try {
        // Fetch product details
        const productResponse = await fetch(`${BASE_URL}/api/products/${productId}`);
        if (!productResponse.ok) {
            throw new Error('Product not found');
        }
        
        const product = await productResponse.json();
        
        // Update page title
        document.title = `${product.name} - Dummy Shopping`;
        
        // Update breadcrumb using category_name from API
        updateBreadcrumb(product.category_name, product.name);
        
        // Highlight active category
        renderCategories();
        
        // Return HTML for product details
        return `
            <div class="product-details">
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
            </div>
        `;
        
    } catch (error) {
        console.error('Error:', error);
        return '<p class="error">Product not found</p>';
    }
}

// 404 handler
function notFoundHandler() {
    document.title = '404 - Page Not Found';
    return '<h1>404 - Page Not Found</h1><p>The page you are looking for does not exist.</p>';
}

// Error handler
function errorHandler(error) {
    document.title = 'Error';
    return `<h1>Error</h1><p>${error.message || 'An unknown error occurred.'}</p>`;
}

// Function to update breadcrumb
function updateBreadcrumb(categoryName, productName) {
    const breadcrumb = document.querySelector('.breadcrumb');
    if (!breadcrumb) return;
    
    breadcrumb.innerHTML = `
        <a href="/">Home</a>
        ${categoryName ? `<span class="separator"> > </span><a href="/?category=${getCategoryId(categoryName)}">${categoryName}</a>` : ''}
        ${productName ? `<span class="separator"> > </span><span>${productName}</span>` : ''}
    `;
}

// Helper to get category ID from name
function getCategoryId(categoryName) {
    const category = categoriesCache.find(c => c.name === categoryName);
    return category ? category.catid : '';
}

// Function to initialize the page structure based on the current path
function initializePageStructure(path) {
    const mainElement = document.querySelector('main');
    if (!mainElement) return;
    
    // Check if we're on the product page
    const isProductPage = path.includes('product.html');
    
    // Check if the required sections exist
    const hasAside = mainElement.querySelector('aside');
    const hasContentSection = isProductPage 
        ? mainElement.querySelector('.product-details')
        : mainElement.querySelector('.product-list');
    
    // If the structure is incomplete, create it
    if (!hasAside || !hasContentSection) {
        mainElement.innerHTML = `
            <aside>
                <h2>Categories</h2>
                <ul></ul>
            </aside>
            <section class="${isProductPage ? 'product-details' : 'product-list'}">
                <div class="loading-indicator">Loading content...</div>
            </section>
        `;
        
        // Re-render categories
        renderCategories();
    }
}