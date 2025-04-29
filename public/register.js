// Define BASE_URL (adjust if needed, ensure consistency with other files)
const BASE_URL = window.location.protocol === 'https:' ? 
    'https://s15.ierg4210.ie.cuhk.edu.hk' : 
    'http://s15.ierg4210.ie.cuhk.edu.hk:3000';

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    const errorMessage = document.getElementById('error-message');

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            errorMessage.textContent = '';
            errorMessage.style.display = 'none';
            errorMessage.className = 'alert alert-danger'; // Default to error

            const emailInput = document.getElementById('email');
            const passwordInput = document.getElementById('password');
            const confirmPasswordInput = document.getElementById('confirm-password');
            const submitButton = registerForm.querySelector('button[type="submit"]');

            const email = emailInput.value;
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;

            // --- Client-side Validation ---
            if (!email || !password || !confirmPassword) {
                errorMessage.textContent = 'Please fill in all fields.';
                errorMessage.style.display = 'block';
                return;
            }

            // Basic email format check (more robust check on server)
            if (!/\S+@\S+\.\S+/.test(email)) {
                 errorMessage.textContent = 'Please enter a valid email address.';
                 errorMessage.style.display = 'block';
                 return;
            }

            if (password.length < 8) {
                errorMessage.textContent = 'Password must be at least 8 characters long.';
                errorMessage.style.display = 'block';
                return;
            }

            if (password !== confirmPassword) {
                errorMessage.textContent = 'Passwords do not match.';
                errorMessage.style.display = 'block';
                return;
            }
            // --- End Validation ---

            try {
                // Disable form during submission
                emailInput.disabled = true;
                passwordInput.disabled = true;
                confirmPasswordInput.disabled = true;
                submitButton.disabled = true;
                submitButton.textContent = 'Registering...';

                console.log(`Attempting registration at: ${BASE_URL}/api/register`);

                const response = await fetch(`${BASE_URL}/api/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                        // No CSRF token typically needed for registration
                    },
                    body: JSON.stringify({ email, password }),
                    // credentials: 'include' // Include if server sets session cookie immediately
                });

                console.log('Register response status:', response.status);
                const data = await response.json(); // Assume server always sends JSON
                console.log('Register response data:', data);

                if (response.ok && data.success) {
                    // Registration successful, server logged user in
                    sessionStorage.setItem('userEmail', data.user.email);
                    sessionStorage.setItem('isAdmin', data.user.isAdmin);
                    
                    // Optional: Show success message before redirect
                    errorMessage.textContent = 'Registration successful! Redirecting...';
                    errorMessage.className = 'alert alert-success';
                    errorMessage.style.display = 'block';

                    // Redirect to home page after a short delay
                    setTimeout(() => {
                        window.location.href = '/'; // Redirect to home page
                    }, 1500);
                
                } else {
                    // Registration failed
                    errorMessage.textContent = data.error || 'Registration failed. Please try again.';
                    errorMessage.style.display = 'block';
                    
                    // Re-enable form
                    emailInput.disabled = false;
                    passwordInput.disabled = false;
                    confirmPasswordInput.disabled = false;
                    submitButton.disabled = false;
                    submitButton.textContent = 'Register';
                }

            } catch (error) {
                console.error('Registration error:', error);
                errorMessage.textContent = 'An error occurred during registration. Please try again.';
                errorMessage.style.display = 'block';
                
                // Re-enable form
                emailInput.disabled = false;
                passwordInput.disabled = false;
                confirmPasswordInput.disabled = false;
                submitButton.disabled = false;
                submitButton.textContent = 'Register';
            }
        });
    }
}); 