console.log('[AdminJS] Initializing, csrfToken should be empty now.');
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
        console.log('[AdminJS fetchCsrfToken] CSRF token fetched and stored:', csrfToken);
    } catch (error) {
        console.error('[AdminJS fetchCsrfToken] Failed to fetch CSRF token:', error);
        csrfToken = 'ERROR_FETCHING_TOKEN';
    }
};

// Apply CSRF token to a fetch request configuration
const applyCsrf = (config = {}) => {
    const newConfig = { ...config };
    newConfig.headers = newConfig.headers || {};
    newConfig.headers['X-CSRF-Token'] = csrfToken;
    console.log('[AdminJS applyCsrf] Applying token to request headers:', csrfToken);
    return newConfig;
};

// Enhanced fetch function with CSRF protection
const safeFetch = async (url, options = {}) => {
    console.log('[AdminJS safeFetch] Called for URL:', url, 'Global csrfToken is:', csrfToken);
    let configWithCsrf = applyCsrf(options);
    let response = await fetch(url, configWithCsrf);

    if (response.status === 403) {
        try {
            const errorData = await response.clone().json();
            if (errorData && errorData.error && errorData.error.toLowerCase().includes('csrf')) {
                console.log('[AdminJS safeFetch] CSRF error detected, attempting token refresh and retry...');
                await fetchCsrfToken();
                configWithCsrf.headers['X-CSRF-Token'] = csrfToken;
                response = await fetch(url, configWithCsrf);
                console.log('[AdminJS safeFetch] Retry response status:', response.status);
            }
        } catch (e) {
            console.warn('[AdminJS safeFetch] Could not parse error response as JSON for 403 or error was not CSRF related.');
        }
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
        // Use relative path for logout to avoid double /api
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
                // No CSRF needed for logout based on server.js logic
            },
            credentials: 'include' // Send session cookies
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
        console.log('[AdminJS DOMContentLoaded] Initial CSRF token fetch complete. Global csrfToken is:', csrfToken);

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

    // Ensure event listener for password change form is attached
    const changePasswordForm = document.getElementById('passwordChangeModalForm'); // Assuming this is the ID of the form *inside* the modal
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', handleChangePasswordSubmit);
        console.log('[AdminJS DOMContentLoaded] Event listener attached to passwordChangeModalForm.');
    } else {
        console.warn('[AdminJS DOMContentLoaded] Password change form (passwordChangeModalForm) not found!');
    }
}); 

// Change Password
const handleChangePasswordSubmit = async (event) => {
    event.preventDefault();
    console.log('[AdminJS handleChangePasswordSubmit] Form submitted. Current global csrfToken:', csrfToken);
    const form = event.target;
    const currentPassword = form.elements['current-password'].value;
    const newPassword = form.elements['new-password'].value;
    const confirmPassword = form.elements['confirm-password'].value;

    if (newPassword !== confirmPassword) {
        showMessage('New passwords do not match.', true);
        return;
    }

    try {
        console.log('[AdminJS handleChangePasswordSubmit] About to call safeFetch. Token is:', csrfToken);
        const responseFromSafeFetch = await safeFetch(`${BASE_URL}/api/change-password`, { 
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        console.log('[AdminJS handleChangePasswordSubmit] Response received, status:', responseFromSafeFetch.status);

        const result = await responseFromSafeFetch.json();
        console.log('[AdminJS handleChangePasswordSubmit] Parsed JSON result:', result);

        if (!responseFromSafeFetch.ok) {
            console.error('[AdminJS handleChangePasswordSubmit] Response not OK. Error from server:', result.error || responseFromSafeFetch.statusText);
            throw new Error(result.error || `Failed to change password: ${responseFromSafeFetch.statusText}`);
        }
        
        console.log('[AdminJS handleChangePasswordSubmit] Password change apparently successful. Server message:', result.message);
        showMessage(result.message || 'Password changed successfully! Please log in again.');
        form.reset();
        console.log('[AdminJS handleChangePasswordSubmit] Form reset. Attempting redirect...');
        window.location.href = '/login.html?status=password_changed';
        console.log('[AdminJS handleChangePasswordSubmit] Redirect initiated.');

    } catch (error) {
        console.error('[AdminJS handleChangePasswordSubmit] Catch block error:', error.message);
        showMessage(error.message || 'An unexpected error occurred.', true);
    }
}; 