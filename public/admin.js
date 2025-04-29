// API endpoints
const API = {
    categories: `${BASE_URL}/categories`,
    products: `${BASE_URL}/products`,
    csrfToken: `${BASE_URL}/csrf-token`
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
        console.log('Fetching categories from:', API.categories);
        const response = await fetch(API.categories);
        console.log('Categories response:', response.status, response.statusText);
        
        if (!response.ok) {
            throw new Error(`Failed to load categories: ${response.status} ${response.statusText}`);
        }
        
        const categories = await response.json();
        console.log('Categories loaded:', categories);
        
        // Update categories list
        const categoriesList = document.getElementById('categories-list');
        if (categories.length === 0) {
            categoriesList.innerHTML = '<p>No categories found. Create your first category using the form above.</p>';
        } else {
            categoriesList.innerHTML = categories.map(category => `
                <div class="category-item">
                    <span>${category.name}</span>
                    <button onclick="editCategory(${category.catid})">Edit</button>
                    <button onclick="deleteCategory(${category.catid})">Delete</button>
                </div>
            `).join('');
        }

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
        console.log('Fetching products from:', API.products);
        const response = await fetch(API.products);
        console.log('Products response:', response.status, response.statusText);
        
        if (!response.ok) {
            throw new Error(`Failed to load products: ${response.status} ${response.statusText}`);
        }
        
        const products = await response.json();
        console.log('Products loaded:', products);
        
        const productsList = document.getElementById('products-list');
        if (products.length === 0) {
            productsList.innerHTML = '<p>No products found. Create your first product using the form above.</p>';
        } else {
            productsList.innerHTML = products.map(product => `
                <div class="product-item">
                    <img src="/uploads/${product.image}" alt="${product.name}" class="preview-image">
                    <span>${product.name} - $${product.price}</span>
                    <button onclick="editProduct(${product.pid})">Edit</button>
                    <button onclick="deleteProduct(${product.pid})">Delete</button>
                </div>
            `).join('');
        }
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

// Handle user logout
const handleLogout = async () => {
    try {
        const response = await safeFetch(`${BASE_URL}/api/logout`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            // Clear session storage
            sessionStorage.removeItem('userEmail');
            sessionStorage.removeItem('isAdmin');
            sessionStorage.removeItem('csrfToken');
            
            // Redirect to login page
            window.location.href = '/login.html';
        } else {
            showMessage('Logout failed. Please try again.', true);
        }
    } catch (error) {
        console.error('Logout error:', error);
        showMessage('An error occurred during logout.', true);
    }
};

// Setup event listeners for user actions
const setupUserActions = () => {
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', (e) => {
            e.preventDefault();
            handleLogout();
        });
    }
    
    const changePasswordButton = document.getElementById('change-password-button');
    if (changePasswordButton) {
        changePasswordButton.addEventListener('click', (e) => {
            e.preventDefault();
            // Reset any previous error messages
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = '';
                errorMessage.style.display = 'none';
            }
            
            // Show password change modal
            const modal = new bootstrap.Modal(document.getElementById('passwordChangeModal'));
            modal.show();
        });
    }
};

// ======================================================
// == Orders Management
// ======================================================
const loadOrders = async () => {
    const ordersTableBody = document.getElementById('orders-table-body');
    if (!ordersTableBody) {
        console.error('Orders table body element not found!');
        return;
    }

    ordersTableBody.innerHTML = '<tr><td colspan="8" class="text-center">Loading orders...</td></tr>'; // Show loading state

    try {
        console.log('Fetching orders from /api/admin/orders');
        const response = await fetch('/api/admin/orders'); // Use relative path or construct from BASE_URL if needed
        console.log('Orders response status:', response.status);

        if (!response.ok) {
             let errorMsg = `Failed to load orders: ${response.status} ${response.statusText}`;
             try {
                 const errorData = await response.json();
                 errorMsg = errorData.error || errorMsg;
             } catch (e) { /* Ignore if response is not JSON */ }
             console.error('Error loading orders:', errorMsg);
             throw new Error(errorMsg);
        }

        const orders = await response.json();
        console.log('Orders loaded:', orders);

        ordersTableBody.innerHTML = ''; // Clear loading/existing rows

        if (orders.length === 0) {
            ordersTableBody.innerHTML = '<tr><td colspan="8" class="text-center">No orders found.</td></tr>';
        } else {
            orders.forEach(order => {
                const row = document.createElement('tr');
                
                // Format date nicely
                const orderDate = new Date(order.order_date).toLocaleString();

                // Create item summary (e.g., "Item1 (x2), Item2 (x1)")
                let itemSummary = order.items.map(item => 
                    `${item.product_name || 'Unknown'} (x${item.quantity})`
                ).join(', ');
                if (itemSummary.length > 50) { // Truncate if too long
                    itemSummary = itemSummary.substring(0, 47) + '...';
                }
                if (!itemSummary) {
                    itemSummary = 'No items recorded';
                }
                
                // Optional: Shorten Stripe Session ID for display
                const shortSessionId = order.stripe_session_id 
                    ? order.stripe_session_id.substring(0, 15) + '...' 
                    : 'N/A';

                row.innerHTML = `
                    <td>${order.order_id}</td>
                    <td>${order.user_email || 'Guest'}</td>
                    <td>${orderDate}</td>
                    <td>${order.total_amount}</td>
                    <td>${order.currency}</td>
                    <td><span class="badge bg-${getStatusColor(order.status)}">${order.status}</span></td>
                    <td title="${order.stripe_session_id || ''}">${shortSessionId}</td>
                    <td title="${order.items.map(i => `${i.product_name}(${i.quantity}) @ ${i.price_at_purchase}`).join('\n')}">${itemSummary}</td>
                `;
                ordersTableBody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error in loadOrders:', error);
        ordersTableBody.innerHTML = `<tr><td colspan="8" class="text-center text-danger">Error loading orders: ${error.message}</td></tr>`;
        showMessage(error.message, true);
    }
};

// Helper function for status badge color
const getStatusColor = (status) => {
    switch (status?.toUpperCase()) {
        case 'COMPLETED': return 'success';
        case 'PENDING': return 'warning';
        case 'FAILED':
        case 'AMOUNT_MISMATCH':
        case 'CURRENCY_MISMATCH':
        case 'INVALID_DIGEST': // Keep old paypal status color
             return 'danger';
        default: return 'secondary';
    }
};

// Initialization
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Admin Panel DOM Loaded');
    
    // Basic auth check (redirect if not admin)
    // This relies on server-side protection for actual security
    const isAdmin = sessionStorage.getItem('isAdmin');
    const userEmail = sessionStorage.getItem('userEmail');

    const authLoader = document.getElementById('auth-loader');
    
    // Fetch auth status from server for robust check
    try {
        const authResponse = await fetch('/api/auth/status', { credentials: 'include' });
        const authData = await authResponse.json();
        
        if (!authResponse.ok || !authData.authenticated || !authData.user?.isAdmin) {
            console.warn('Authentication failed or user is not admin. Redirecting to login.');
            window.location.href = '/login.html?error=admin_required';
            return; // Stop further execution
        }
        
        // Auth successful, show page content
        document.body.style.visibility = 'visible';
        if(authLoader) authLoader.style.display = 'none'; // Hide loader
        console.log('Admin Authentication successful for:', authData.user.email);
        document.getElementById('user-email').textContent = authData.user.email;
        
        // Now fetch CSRF token since user is authenticated
        await fetchCsrfToken();
        
        // Inject CSRF token into forms
        const csrfCategoryPlaceholder = document.getElementById('csrf-category-placeholder');
        const csrfProductPlaceholder = document.getElementById('csrf-product-placeholder');
        if (csrfCategoryPlaceholder) {
            csrfCategoryPlaceholder.innerHTML = `<input type="hidden" name="_csrf" value="${csrfToken}">`;
        }
        if (csrfProductPlaceholder) {
            csrfProductPlaceholder.innerHTML = `<input type="hidden" name="_csrf" value="${csrfToken}">`;
        }

    } catch (error) {
        console.error('Error checking auth status:', error);
        if(authLoader) authLoader.innerHTML = '<p class="text-danger">Error validating authentication. Please try logging in again.</p>';
        // Optionally redirect after a delay
        // setTimeout(() => window.location.href = '/login.html?error=auth_check_failed', 3000);
        return; // Stop if auth check fails
    }

    // Attach form handlers
    const categoryForm = document.getElementById('category-form');
    const productForm = document.getElementById('product-form');
    
    if (categoryForm) categoryForm.addEventListener('submit', handleCategorySubmit);
    if (productForm) productForm.addEventListener('submit', handleProductSubmit);

    // Setup user actions (logout, change password)
    setupUserActions();
    
    // Load initial data
    try {
        await loadCategories(); // Load categories first for product form dropdown
        await loadProducts();
        await loadOrders(); // <<< CALL loadOrders HERE
    } catch (error) {
        console.error("Error loading initial admin data:", error);
        showMessage("Failed to load some admin data. Please check console.", true);
    }
}); 