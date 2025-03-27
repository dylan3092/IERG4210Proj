// Client-side router to prevent full page reloads
class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;
        this.contentContainer = null;
        this.eventListeners = {};
        
        // Handle browser back/forward buttons
        window.addEventListener('popstate', (event) => {
            this.handleRouteChange(window.location.pathname + window.location.search);
        });
    }

    // Event handling methods
    on(event, callback) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(callback);
    }

    emit(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => callback(data));
        }
    }

    // Initialize the router
    init(contentContainer) {
        this.contentContainer = document.querySelector(contentContainer);
        if (!this.contentContainer) {
            console.error('Content container not found:', contentContainer);
            return;
        }

        // Intercept all internal links
        document.addEventListener('click', (event) => {
            // Find closest anchor tag
            const link = event.target.closest('a');
            if (!link) return;

            // Skip external links or links with modifiers
            if (link.hostname !== window.location.hostname || 
                event.ctrlKey || event.metaKey || event.shiftKey) {
                return;
            }

            // Prevent default link behavior
            event.preventDefault();

            // Navigate to the link
            this.navigate(link.href);
        });

        // Handle initial route
        this.handleRouteChange(window.location.pathname + window.location.search);
    }

    // Register a route handler
    register(path, handler) {
        this.routes[path] = handler;
    }

    // Navigate to a new route
    navigate(url) {
        const parsedUrl = new URL(url);
        const path = parsedUrl.pathname + parsedUrl.search;
        
        // Update browser history
        window.history.pushState({}, '', url);
        
        // Handle the route change
        this.handleRouteChange(path);
    }

    // Handle route changes
    async handleRouteChange(path) {
        // Show loading state
        if (this.contentContainer) {
            this.contentContainer.classList.add('loading');
        }
        
        // Check if we need to initialize the page structure
        if (typeof initializePageStructure === 'function') {
            initializePageStructure(path);
        }
        
        // Find matching route handler
        let handler = null;
        let params = {};
        
        // Normalize path by removing leading slash
        const normalizedPath = path.startsWith('/') ? path.substring(1) : path;
        
        // Check for exact match first
        if (this.routes[normalizedPath]) {
            handler = this.routes[normalizedPath];
        } else if (this.routes['/'+normalizedPath]) {
            handler = this.routes['/'+normalizedPath];
        } else {
            // Check for pattern matches (e.g., /product/:id)
            for (const [pattern, routeHandler] of Object.entries(this.routes)) {
                const match = this.matchRoute(pattern, normalizedPath);
                if (match) {
                    handler = routeHandler;
                    params = match;
                    break;
                }
            }
        }

        // If no handler found, use the 404 handler
        if (!handler && this.routes['404']) {
            handler = this.routes['404'];
        }

        // Execute the handler
        if (handler) {
            try {
                this.currentRoute = path;
                const content = await handler(params);
                
                // Update only the content section, not the entire main element
                if (content && this.contentContainer) {
                    // Check if we're on the home page or product page
                    const isProductPage = path.includes('product.html');
                    
                    // Find the appropriate content section to update
                    const contentSection = isProductPage 
                        ? this.contentContainer.querySelector('.product-details') 
                        : this.contentContainer.querySelector('.product-list');
                    
                    if (contentSection) {
                        contentSection.innerHTML = content;
                    } else {
                        // If the section doesn't exist yet, we need to create the structure
                        this.contentContainer.innerHTML = `
                            <aside>
                                <h2>Categories</h2>
                                <ul></ul>
                            </aside>
                            <section class="${isProductPage ? 'product-details' : 'product-list'}">
                                ${content}
                            </section>
                        `;
                        
                        // After creating the structure, we need to re-render categories
                        if (typeof renderCategories === 'function') {
                            renderCategories();
                        }
                    }
                }
                
                // Emit route changed event
                this.emit('routeChanged', { path, params });
                
            } catch (error) {
                console.error('Error handling route:', error);
                if (this.routes['error'] && this.contentContainer) {
                    const errorSection = this.contentContainer.querySelector('.product-list') || 
                                        this.contentContainer.querySelector('.product-details');
                    if (errorSection) {
                        errorSection.innerHTML = await this.routes['error'](error);
                    }
                }
            }
        }

        // Remove loading state
        if (this.contentContainer) {
            this.contentContainer.classList.remove('loading');
        }
    }

    // Match route patterns (e.g., /product/:id)
    matchRoute(pattern, path) {
        // Convert pattern to regex
        const patternParts = pattern.split('/');
        const pathParts = path.split('?')[0].split('/');
        
        // If parts length doesn't match, return null
        if (patternParts.length !== pathParts.length) {
            return null;
        }
        
        const params = {};
        
        // Match each part
        for (let i = 0; i < patternParts.length; i++) {
            const patternPart = patternParts[i];
            const pathPart = pathParts[i];
            
            // If pattern part starts with :, it's a parameter
            if (patternPart.startsWith(':')) {
                const paramName = patternPart.substring(1);
                params[paramName] = pathPart;
            } 
            // Otherwise, it should match exactly
            else if (patternPart !== pathPart) {
                return null;
            }
        }
        
        // Add query params
        const queryParams = new URLSearchParams(path.split('?')[1] || '');
        queryParams.forEach((value, key) => {
            params[key] = value;
        });
        
        return params;
    }

    // Get current route
    getCurrentRoute() {
        return this.currentRoute;
    }

    // Get query parameters
    getQueryParams() {
        const searchParams = new URLSearchParams(window.location.search);
        const params = {};
        
        searchParams.forEach((value, key) => {
            params[key] = value;
        });
        
        return params;
    }
}

// Create global router instance
const router = new Router();

// Export for use in other modules
window.router = router; 