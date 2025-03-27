document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const passwordChangeForm = document.getElementById('password-change-form');
    const errorMessage = document.getElementById('error-message');
    
    // Check if already logged in
    fetch('/api/categories')
        .then(response => {
            if (response.ok) {
                // Already authenticated, redirect to admin page
                window.location.href = '/admin.html';
            }
        })
        .catch(error => console.error('Auth check error:', error));
    
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            errorMessage.textContent = '';
            errorMessage.style.display = 'none';
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Store user information in session storage
                    sessionStorage.setItem('userEmail', data.user.email);
                    sessionStorage.setItem('isAdmin', data.user.isAdmin);
                    
                    // Redirect to admin panel
                    window.location.href = '/admin.html';
                } else {
                    // Show error message
                    errorMessage.textContent = data.error || 'Login failed. Please try again.';
                    errorMessage.style.display = 'block';
                }
            } catch (error) {
                console.error('Login error:', error);
                errorMessage.textContent = 'An error occurred. Please try again.';
                errorMessage.style.display = 'block';
            }
        });
    }
    
    if (passwordChangeForm) {
        passwordChangeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            // Check if passwords match
            if (newPassword !== confirmPassword) {
                errorMessage.textContent = 'New passwords do not match';
                errorMessage.style.display = 'block';
                return;
            }
            
            try {
                const csrfToken = sessionStorage.getItem('csrfToken');
                const response = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ currentPassword, newPassword })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Show success message and close modal
                    const successMessage = document.getElementById('success-message');
                    if (successMessage) {
                        successMessage.textContent = 'Password changed successfully';
                        successMessage.style.display = 'block';
                    }
                    
                    // Clear form fields
                    document.getElementById('current-password').value = '';
                    document.getElementById('new-password').value = '';
                    document.getElementById('confirm-password').value = '';
                    
                    // Close modal after delay
                    setTimeout(() => {
                        const modal = new bootstrap.Modal(document.getElementById('passwordChangeModal'));
                        modal.hide();
                        if (successMessage) {
                            successMessage.style.display = 'none';
                        }
                    }, 2000);
                } else {
                    // Show error message
                    errorMessage.textContent = data.error || 'Failed to change password. Please try again.';
                    errorMessage.style.display = 'block';
                }
            } catch (error) {
                console.error('Password change error:', error);
                errorMessage.textContent = 'An error occurred. Please try again.';
                errorMessage.style.display = 'block';
            }
        });
    }
}); 