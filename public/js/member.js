document.addEventListener('DOMContentLoaded', async () => {
    console.log('[MemberJS] DOMContentLoaded');
    const authLoader = document.getElementById('auth-loader');
    const userEmailDisplay = document.getElementById('user-email');

    // API endpoints (adjust if BASE_URL is different or not used)
    // Since BASE_URL in member.html is '', full paths from root are needed.
    const API = {
        userOrders: '/api/user/orders', // Using the existing endpoint
        csrfToken: '/api/csrf-token',
        changePassword: '/api/change-password', // Using existing endpoint
        logout: '/api/logout', // Using existing endpoint
        authStatus: '/api/auth/status'
    };

    let csrfToken = '';

    // --- Helper Functions (adapted from admin.js) ---
    const fetchCsrfToken = async () => {
        try {
            const response = await fetch(API.csrfToken);
            if (!response.ok) throw new Error('Failed to fetch CSRF token, server responded with ' + response.status);
            const data = await response.json();
            csrfToken = data.csrfToken;
            console.log('[MemberJS fetchCsrfToken] CSRF token fetched:', csrfToken);
        } catch (error) {
            console.error('[MemberJS fetchCsrfToken] Error:', error.message);
            csrfToken = 'ERROR_FETCHING_TOKEN'; // Fallback
            showMessage('Critical: Could not obtain CSRF token. Some actions may fail.', true, null, true);
        }
    };

    const applyCsrf = (config = {}) => {
        const newConfig = { ...config };
        newConfig.headers = newConfig.headers || {};
        newConfig.headers['X-CSRF-Token'] = csrfToken;
        return newConfig;
    };

    const safeFetch = async (url, options = {}) => {
        console.log('[MemberJS safeFetch] Called for URL:', url, 'Global csrfToken is:', csrfToken);
        if (csrfToken === 'ERROR_FETCHING_TOKEN' && (options.method === 'POST' || options.method === 'PUT' || options.method === 'DELETE')) {
            showMessage('Action blocked: CSRF token is missing or invalid. Please refresh.', true, null, true);
            throw new Error('CSRF token missing or invalid.');
        }
        let configWithCsrf = applyCsrf(options);
        let response = await fetch(url, configWithCsrf);

        if (response.status === 403) { // Check for CSRF error specifically
            try {
                const errorData = await response.clone().json(); // Use clone to be able to read body again
                if (errorData && errorData.error && errorData.error.toLowerCase().includes('csrf')) {
                    console.warn('[MemberJS safeFetch] CSRF error detected. Attempting to refresh token and retry.');
                    await fetchCsrfToken(); // Refresh token
                    if (csrfToken === 'ERROR_FETCHING_TOKEN') { // Check if refresh failed
                         showMessage('CSRF token refresh failed. Action cannot be completed.', true, null, true);
                         throw new Error('CSRF token refresh failed.');
                    }
                    configWithCsrf.headers['X-CSRF-Token'] = csrfToken; // Update header with new token
                    response = await fetch(url, configWithCsrf); // Retry the request
                    console.log('[MemberJS safeFetch] Retry response status:', response.status);
                }
            } catch (e) {
                console.warn('[MemberJS safeFetch] Error while handling 403 or error was not CSRF related:', e.message);
                // If it's not a JSON response or not a CSRF error, the original response will be returned.
            }
        }
        return response;
    };
    
    // Unified message display (targets specific message areas or a general one)
    const showMessage = (message, isError = false, elementId = null, isCritical = false) => {
        let messageDiv;
        if (elementId) {
            messageDiv = document.getElementById(elementId);
        }
        
        if (!messageDiv) { // Fallback to a generic message display if elementId is not provided or not found
            const existingGenericMsg = document.getElementById('generic-message-area');
            if (existingGenericMsg) {
                messageDiv = existingGenericMsg;
            } else {
                messageDiv = document.createElement('div');
                messageDiv.id = 'generic-message-area';
                messageDiv.style.position = 'fixed';
                messageDiv.style.top = '20px';
                messageDiv.style.right = '20px';
                messageDiv.style.zIndex = '1050'; // Ensure it's above most elements
                messageDiv.style.minWidth = '250px';
                document.body.appendChild(messageDiv);
            }
        }

        const alertType = isError ? (isCritical ? 'alert-danger' : 'alert-warning') : 'alert-success';
        messageDiv.innerHTML = `<div class="alert ${alertType} alert-dismissible fade show" role="alert">
                                ${message}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                              </div>`;
        messageDiv.style.display = 'block';

        if (!isCritical) { // Auto-hide non-critical messages
            setTimeout(() => {
                const alertInstance = bootstrap.Alert.getInstance(messageDiv.firstChild);
                if (alertInstance) {
                    alertInstance.close();
                } else if (messageDiv.firstChild) { // Fallback if instance not found
                    messageDiv.firstChild.remove();
                }
            }, 5000);
        }
    };

    // --- Authentication Check ---
    try {
        const authResponse = await fetch(API.authStatus, { credentials: 'include' });
        const authData = await authResponse.json();

        if (!authResponse.ok || !authData.authenticated) {
            console.warn('[MemberJS Auth] Not authenticated. Redirecting to login.');
            window.location.href = '/login.html?error=member_login_required';
            return;
        }
        if (authData.user && authData.user.isAdmin) {
            console.warn('[MemberJS Auth] User is admin. Redirecting to admin panel.');
            // Optional: Or just show a message and let them stay if preferred
            window.location.href = '/admin.html?info=admin_access_redirected_to_admin_panel';
            return;
        }

        // Auth successful for a non-admin user
        if(userEmailDisplay) userEmailDisplay.textContent = authData.user.email || 'Member';
        document.body.style.visibility = 'visible';
        if(authLoader) authLoader.style.display = 'none';
        console.log('[MemberJS Auth] Authenticated as member:', authData.user.email);

        // Fetch CSRF token now that user is authenticated
        await fetchCsrfToken();
        if (csrfToken === 'ERROR_FETCHING_TOKEN') {
             // Handled by showMessage in fetchCsrfToken
            return; // Stop further execution if CSRF token is critical and failed
        }

    } catch (error) {
        console.error('[MemberJS Auth] Error checking auth status:', error);
        if(authLoader) {
            authLoader.innerHTML = '<p class="text-danger">Error validating your session. Please try <a href="/login.html">logging in</a> again.</p>';
        }
        // Potentially redirect or show a persistent error message
        return; // Stop if auth check fails
    }

    // --- Load User Orders ---
    const loadUserOrders = async () => {
        const ordersListDiv = document.getElementById('orders-list');
        ordersListDiv.innerHTML = '<p class="text-center">Loading your orders...</p>';
        try {
            const response = await fetch(API.userOrders, { credentials: 'include' }); // CSRF not typically needed for GET
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `Failed to load orders. Server responded with ${response.status}` }));
                throw new Error(errorData.error);
            }
            const orders = await response.json();
            renderOrders(orders);
        } catch (error) {
            console.error('[MemberJS loadUserOrders] Error:', error.message);
            ordersListDiv.innerHTML = `<p class="text-center text-danger">Could not load your orders: ${error.message}</p>`;
            showMessage(`Failed to load orders: ${error.message}`, true, 'orders-list-message'); // Example of specific message area
        }
    };

    const renderOrders = (orders) => {
        const ordersListDiv = document.getElementById('orders-list');
        ordersListDiv.innerHTML = ''; // Clear loading message

        if (!orders || orders.length === 0) {
            ordersListDiv.innerHTML = '<p class="text-center">You have no orders yet.</p>';
            return;
        }

        orders.forEach(order => {
            const orderDate = new Date(order.order_date).toLocaleString();
            let itemSummary = 'No items recorded';
            if (order.items && order.items.length > 0) {
                itemSummary = order.items.map(item => 
                    `<li>${item.product_name || 'Unknown Product'} (x${item.quantity}) - ${order.currency} ${parseFloat(item.price_at_purchase).toFixed(2)} each</li>`
                ).join('');
            }

            const orderElement = document.createElement('div');
            orderElement.className = 'order-item card mb-3';
            orderElement.innerHTML = `
                <div class="card-header d-flex justify-content-between align-items-center">
                    <strong>Order ID: ${order.order_id}</strong>
                    <span class="badge bg-${getStatusColor(order.status)}">${order.status}</span>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6 order-details">
                            <p><strong>Date:</strong> ${orderDate}</p>
                            <p><strong>Total:</strong> ${order.currency} ${parseFloat(order.total_amount).toFixed(2)}</p>
                            ${order.stripe_session_id ? `<p><small>Ref: ${order.stripe_session_id.substring(0,20)}...</small></p>` : ''}
                        </div>
                        <div class="col-md-6">
                            <h6>Items:</h6>
                            <ul class="item-list">
                                ${itemSummary}
                            </ul>
                        </div>
                    </div>
                </div>
            `;
            ordersListDiv.appendChild(orderElement);
        });
    };
    
    // Helper function for status badge color (consistent with admin panel)
    const getStatusColor = (status) => {
        switch (status?.toUpperCase()) {
            case 'COMPLETED': return 'success';
            case 'PENDING': return 'warning';
            case 'PAID': return 'info'; // Assuming PAID is a possible status after checkout before completion
            case 'FAILED':
            case 'CANCELLED': // Added CANCELLED
            case 'AMOUNT_MISMATCH':
            case 'CURRENCY_MISMATCH':
                 return 'danger';
            default: return 'secondary';
        }
    };


    // --- Change Password ---
    const handleChangePasswordSubmit = async (event) => {
        event.preventDefault();
        const form = event.target;
        const currentPassword = form.elements['currentPassword'].value;
        const newPassword = form.elements['newPassword'].value;
        const confirmPassword = form.elements['confirmPassword'].value;
        const messageArea = document.getElementById('password-change-message');

        if (newPassword !== confirmPassword) {
            showMessage('New passwords do not match.', true, 'password-change-message');
            return;
        }
        if (!newPassword || newPassword.length < 6) { // Basic validation
            showMessage('New password must be at least 6 characters long.', true, 'password-change-message');
            return;
        }

        try {
            console.log('[MemberJS handleChangePasswordSubmit] Submitting. CSRF Token:', csrfToken);
            const response = await safeFetch(API.changePassword, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ currentPassword, newPassword, _csrf: csrfToken }) // Ensure CSRF is in body if server expects
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || `Failed to change password (${response.status})`);
            }
            
            showMessage(result.message || 'Password changed successfully! Please log in again.', false, 'password-change-message');
            form.reset();
            
            // Close modal after a short delay
            setTimeout(() => {
                const modalElement = document.getElementById('passwordChangeModal');
                const modalInstance = bootstrap.Modal.getInstance(modalElement);
                if (modalInstance) modalInstance.hide();
                 // Redirect to login as session is likely invalidated
                window.location.href = '/login.html?status=password_changed_member';
            }, 2000);

        } catch (error) {
            console.error('[MemberJS handleChangePasswordSubmit] Error:', error.message);
            showMessage(error.message || 'An unexpected error occurred.', true, 'password-change-message');
        }
    };

    // --- Logout ---
    const handleLogout = async () => {
        try {
            // CSRF for logout if your server requires it (often POST logout does)
            // Assuming /api/logout is a POST and needs CSRF from previous discussions
            const response = await safeFetch(API.logout, {
                 method: 'POST',
                 // body: JSON.stringify({ _csrf: csrfToken }), // If server expects CSRF in body
                 // headers: { 'Content-Type': 'application/json' } // If sending JSON body
            });


            if (response.ok) {
                sessionStorage.clear(); // Clear any session storage on client
                window.location.href = '/login.html?status=logged_out';
            } else {
                const errorData = await response.json().catch(() => ({error: 'Logout failed.'}));
                showMessage(`Logout failed: ${errorData.error}. Please try again.`, true);
            }
        } catch (error) {
            console.error('[MemberJS handleLogout] Error:', error.message);
            showMessage('An error occurred during logout.', true);
        }
    };

    // --- Event Listeners ---
    const goToShopButton = document.getElementById('go-to-shop-button');
    if (goToShopButton) {
        goToShopButton.addEventListener('click', () => {
            window.location.href = '/index.html'; // Or just '/' if that's your shop root
        });
    }

    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) logoutButton.addEventListener('click', handleLogout);

    const passwordChangeForm = document.getElementById('password-change-form');
    if (passwordChangeForm) {
        passwordChangeForm.addEventListener('submit', handleChangePasswordSubmit);
    } else {
        console.warn('[MemberJS] Password change form (password-change-form) not found!');
    }
    
    // --- Initial Data Load ---
    if (csrfToken !== 'ERROR_FETCHING_TOKEN') { // Only load data if CSRF is fine
        await loadUserOrders();
    } else {
        document.getElementById('orders-list').innerHTML = '<p class="text-center text-danger">Cannot load orders due to a security token issue. Please refresh the page.</p>';
    }
}); 