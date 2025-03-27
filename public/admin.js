// API endpoints
const API = {
    categories: '/api/categories',
    products: '/api/products',
    csrfToken: '/api/csrf-token' // New endpoint for CSRF token
};

// CSRF token management
let csrfToken = '';

// Fetch CSRF token on page load
const fetchCsrfToken = async () => {
    try {
        const response = await fetch(API.csrfToken);
        const data = await response.json();
        csrfToken = data.csrfToken;
        console.log('CSRF token fetched');
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
    }
};

// Apply CSRF token to a fetch request configuration
const applyCsrf = (config = {}) => {
    // Create a new config object to avoid modifying the original
    const newConfig = { ...config };
    
    // Initialize headers if they don't exist
    newConfig.headers = newConfig.headers || {};
    
    // Add CSRF token as a header
    newConfig.headers['X-CSRF-Token'] = csrfToken;
    
    return newConfig;
};

// Enhanced fetch function with CSRF protection
const safeFetch = async (url, options = {}) => {
    // Apply CSRF token to the request
    const configWithCsrf = applyCsrf(options);
    
    // Make the request
    const response = await fetch(url, configWithCsrf);
    
    // If token is expired or invalid, try to refresh it and retry once
    if (response.status === 403 && response.statusText.includes('CSRF')) {
        await fetchCsrfToken();
        configWithCsrf.headers['X-CSRF-Token'] = csrfToken;
        return fetch(url, configWithCsrf);
    }
    
    return response;
};

// Utility functions
const handleResponse = async (response) => {
    if (!response.ok) {
        const error = await response.text();
        throw new Error(error);
    }
    return response.json();
};

const showMessage = (message, isError = false) => {
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message;
    messageDiv.className = isError ? 'error' : 'success';
    document.body.insertBefore(messageDiv, document.body.firstChild);
    setTimeout(() => messageDiv.remove(), 3000);
};

// Categories Management
const loadCategories = async () => {
    try {
        const categories = await fetch(API.categories).then(handleResponse);
        
        // Update categories list
        const categoriesList = document.getElementById('categories-list');
        categoriesList.innerHTML = categories.map(category => `
            <div class="category-item">
                <span>${category.name}</span>
                <button onclick="editCategory(${category.catid})">Edit</button>
                <button onclick="deleteCategory(${category.catid})">Delete</button>
            </div>
        `).join('');

        // Update product form category dropdown
        const categorySelect = document.getElementById('product-category');
        categorySelect.innerHTML = categories.map(category =>
            `<option value="${category.catid}">${category.name}</option>`
        ).join('');
    } catch (error) {
        showMessage(error.message, true);
    }
};

const handleCategorySubmit = async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    
    try {
        const catid = formData.get('catid');
        
        // Add CSRF token to the data
        const jsonData = {
            name: formData.get('name'),
            _csrf: csrfToken // Include CSRF token in the request body
        };
        
        const response = await safeFetch(API.categories + (catid ? `/${catid}` : ''), {
            method: catid ? 'PUT' : 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(jsonData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to save category');
        }

        const result = await response.json();
        showMessage(`Category ${catid ? 'updated' : 'created'} successfully`);
        event.target.reset();
        loadCategories();
    } catch (error) {
        showMessage(error.message, true);
    }
};

const editCategory = async (catid) => {
    try {
        const category = await fetch(`${API.categories}/${catid}`).then(handleResponse);
        document.getElementById('category-id').value = category.catid;
        document.getElementById('category-name').value = category.name;
    } catch (error) {
        showMessage(error.message, true);
    }
};

const deleteCategory = async (catid) => {
    if (!confirm('Are you sure you want to delete this category?')) return;
    
    try {
        await safeFetch(`${API.categories}/${catid}`, {
            method: 'DELETE'
        }).then(handleResponse);

        showMessage('Category deleted successfully');
        loadCategories();
    } catch (error) {
        showMessage(error.message, true);
    }
};

// Products Management
const loadProducts = async () => {
    try {
        const products = await fetch(API.products).then(handleResponse);
        
        const productsList = document.getElementById('products-list');
        productsList.innerHTML = products.map(product => `
            <div class="product-item">
                <img src="/uploads/${product.image}" alt="${product.name}" class="preview-image">
                <span>${product.name} - $${product.price}</span>
                <button onclick="editProduct(${product.pid})">Edit</button>
                <button onclick="deleteProduct(${product.pid})">Delete</button>
            </div>
        `).join('');
    } catch (error) {
        showMessage(error.message, true);
    }
};

const handleProductSubmit = async (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    
    // Add CSRF token to form data
    formData.append('_csrf', csrfToken);
    
    try {
        const pid = formData.get('pid');
        const response = await safeFetch(API.products + (pid ? `/${pid}` : ''), {
            method: pid ? 'PUT' : 'POST',
            body: formData // Send FormData directly for file upload
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to save product');
        }

        const result = await response.json();
        showMessage(`Product ${pid ? 'updated' : 'created'} successfully`);
        event.target.reset();
        document.getElementById('image-preview').innerHTML = '';
        loadProducts();
    } catch (error) {
        showMessage(error.message, true);
    }
};

const editProduct = async (pid) => {
    try {
        const product = await fetch(`${API.products}/${pid}`).then(handleResponse);
        document.getElementById('product-id').value = product.pid;
        document.getElementById('product-category').value = product.catid;
        document.getElementById('product-name').value = product.name;
        document.getElementById('product-price').value = product.price;
        document.getElementById('product-description').value = product.description;
        
        if (product.image) {
            const preview = document.getElementById('image-preview');
            preview.innerHTML = `<img src="/uploads/${product.image}" class="preview-image">`;
        }
    } catch (error) {
        showMessage(error.message, true);
    }
};

const deleteProduct = async (pid) => {
    if (!confirm('Are you sure you want to delete this product?')) return;
    
    try {
        await safeFetch(`${API.products}/${pid}`, {
            method: 'DELETE'
        }).then(handleResponse);

        showMessage('Product deleted successfully');
        loadProducts();
    } catch (error) {
        showMessage(error.message, true);
    }
};

// Image preview
document.getElementById('product-image').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
        if (file.size > 10 * 1024 * 1024) {
            showMessage('Image size must be less than 10MB', true);
            event.target.value = '';
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const preview = document.getElementById('image-preview');
            preview.innerHTML = `<img src="${e.target.result}" class="preview-image">`;
        };
        reader.readAsDataURL(file);
    }
});

// Initialize forms
document.getElementById('category-form').addEventListener('submit', handleCategorySubmit);
document.getElementById('product-form').addEventListener('submit', handleProductSubmit);

// First, fetch the CSRF token, then load initial data
(async () => {
    await fetchCsrfToken();
    
    // Inject CSRF tokens into the forms
    const categoryPlaceholder = document.getElementById('csrf-category-placeholder');
    const productPlaceholder = document.getElementById('csrf-product-placeholder');
    
    if (categoryPlaceholder) {
        categoryPlaceholder.innerHTML = `<input type="hidden" name="_csrf" value="${csrfToken}">`;
    }
    
    if (productPlaceholder) {
        productPlaceholder.innerHTML = `<input type="hidden" name="_csrf" value="${csrfToken}">`;
    }
    
    // Load data after CSRF setup is complete
    loadCategories();
    loadProducts();
})(); 