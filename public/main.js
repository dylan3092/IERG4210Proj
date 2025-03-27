// Global state for categories
let categoriesCache = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize router with a more specific selector
    router.init('main');
    
    // Register routes
    router.register('/', homeHandler);
    router.register('', homeHandler); // Handle empty path
    router.register('index.html', homeHandler);
    router.register('/index.html', homeHandler);
    router.register('product.html', productHandler);
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
        
        if (!response.ok) {
            console.error('Failed to load categories:', response.status, response.statusText);
            const categoryLists = document.querySelectorAll('aside ul');
            
            // If the error is due to authentication, suggest logging in
            if (response.status === 401) {
                categoryLists.forEach(list => {
                    list.innerHTML = `
                        <li class="error">Login required to view categories</li>
                        <li><a href="login.html" class="login-btn">Login</a></li>
                    `;
                });
            } else {
                categoryLists.forEach(list => {
                    list.innerHTML = '<li class="error">Error loading categories</li>';
                });
            }
            
            return [];
        }
        
        categoriesCache = await response.json();
        
        // Render categories in sidebar
        renderCategories();
        
        return categoriesCache;
    } catch (error) {
        console.error('Error fetching categories:', error);
        const categoryLists = document.querySelectorAll('aside ul');
        categoryLists.forEach(list => {
            list.innerHTML = '<li class="error">Error loading categories</li>';
        });
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
                <a href="index.html" class="${!currentCategoryId ? 'active' : ''}">
                    All Products
                </a>
            </li>
        `;
        
        // Add the rest of the categories
        categoriesHTML += categoriesCache.map(category => {
            const isActive = currentCategoryId == category.catid;
            return `
                <li>
                    <a href="index.html?category=${sanitize.attribute(category.catid)}" 
                       class="${isActive ? 'active' : ''}">
                        ${sanitize.html(category.name)}
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
            ? `${BASE_URL}/api/products?category=${sanitize.html(categoryId)}`
            : `${BASE_URL}/api/products`;
            
        const response = await fetch(productsUrl);
        
        if (!response.ok) {
            console.error('Failed to load products:', response.status, response.statusText);
            
            // If the error is due to authentication, suggest logging in
            if (response.status === 401) {
                return `
                    <p class="error">You need to be logged in to view products.</p>
                    <p><a href="login.html" class="btn btn-primary">Login</a></p>
                `;
            }
            
            return `<p class="error">Error loading products. Server returned: ${response.status} ${response.statusText}</p>`;
        }
        
        const products = await response.json();
        
        // Update page title and breadcrumb based on category
        if (categoryId) {
            const selectedCategory = categoriesCache.find(c => c.catid == categoryId);
            if (selectedCategory) {
                document.title = `${sanitize.html(selectedCategory.name)} - Dummy Shopping`;
                updateBreadcrumb(sanitize.html(selectedCategory.name));
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
                    <a href="product.html?product=${sanitize.attribute(product.pid)}">
                        <img src="${product.thumbnail ? 
                            sanitize.url(`${BASE_URL}/uploads/${product.thumbnail}`) : 
                            'images/default.jpg'}" 
                            alt="${sanitize.html(product.name)}" width="150" height="150">
                        <h3>${sanitize.html(product.name)}</h3>
                    </a>
                    <p class="price">$${sanitize.html(price.toFixed(2))}</p>
                    <button type="button" onclick="addToCart(${sanitize.attribute(product.pid)}, 1)">Add to Cart</button>
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
        router.navigate('index.html');
        return '';
    }
    
    try {
        // Fetch product details
        const productResponse = await fetch(`${BASE_URL}/api/products/${sanitize.html(productId)}`);
        if (!productResponse.ok) {
            throw new Error('Product not found');
        }
        
        const product = await productResponse.json();
        
        // Update page title
        document.title = `${sanitize.html(product.name)} - Dummy Shopping`;
        
        // Update breadcrumb using category_name from API
        updateBreadcrumb(sanitize.html(product.category_name), sanitize.html(product.name));
        
        // Highlight active category
        renderCategories();
        
        // Return HTML for product details
        return `
            <div class="product-details">
                <div class="product-image">
                    <img src="${product.image ? 
                        sanitize.url(`${BASE_URL}/uploads/${product.image}`) : 
                        'images/default.jpg'}" 
                        alt="${sanitize.html(product.name)}">
                </div>
                <div class="product-info">
                    <h1>${sanitize.html(product.name)}</h1>
                    <p class="category">Category: ${sanitize.html(product.category_name)}</p>
                    <p class="price">$${sanitize.html(Number(product.price).toFixed(2))}</p>
                    <p class="description">${sanitize.html(product.description)}</p>
                    <div class="purchase-controls">
                        <input type="number" id="quantity" value="1" min="1" max="99">
                        <button onclick="addToCart(${sanitize.attribute(product.pid)}, document.getElementById('quantity').value)">
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
    return `<h1>Error</h1><p>${sanitize.html(error.message || 'An unknown error occurred.')}</p>`;
}

// Function to update breadcrumb
function updateBreadcrumb(categoryName, productName) {
    const breadcrumb = document.querySelector('.breadcrumb');
    if (!breadcrumb) return;
    
    breadcrumb.innerHTML = `
        <a href="index.html">Home</a>
        ${categoryName ? `<span class="separator"> > </span><a href="index.html?category=${sanitize.attribute(getCategoryId(categoryName))}">${sanitize.html(categoryName)}</a>` : ''}
        ${productName ? `<span class="separator"> > </span><span>${sanitize.html(productName)}</span>` : ''}
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