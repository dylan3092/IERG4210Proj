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

            // Skip external links or links with modifiers or login pages
            if (link.hostname !== window.location.hostname || 
                event.ctrlKey || event.metaKey || event.shiftKey ||
                link.href.includes('login.html')) {
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
        console.log(`Router handling path: ${path}`);
        
        // Show loading state
        if (this.contentContainer) {
            this.contentContainer.classList.add('loading');
            console.log("Added loading class");
        } else {
            console.error("Content container not found!", this.contentContainer);
        }
        
        // Check if we need to initialize the page structure
        if (typeof initializePageStructure === 'function') {
            console.log("Initializing page structure");
            initializePageStructure(path);
        } else {
            console.error("initializePageStructure function not found");
        }
        
        // Find matching route handler
        let handler = null;
        let params = {};
        
        // Normalize path by removing leading slash
        const normalizedPath = path.startsWith('/') ? path.substring(1) : path;
        console.log(`Normalized path: ${normalizedPath}`);
        
        // Log registered routes for debugging
        console.log('Registered routes:', Object.keys(this.routes));
        
        // Check for exact match first
        if (this.routes[normalizedPath]) {
            console.log(`Found exact route handler for: ${normalizedPath}`);
            handler = this.routes[normalizedPath];
        } else if (this.routes['/'+normalizedPath]) {
            console.log(`Found slash-prefixed route handler for: /${normalizedPath}`);
            handler = this.routes['/'+normalizedPath];
        } else {
            // Check for pattern matches (e.g., /product/:id)
            console.log("Checking pattern matches");
            for (const [pattern, routeHandler] of Object.entries(this.routes)) {
                console.log(`Checking pattern: ${pattern}`);
                const match = this.matchRoute(pattern, normalizedPath);
                if (match) {
                    console.log(`Matched pattern: ${pattern}`);
                    handler = routeHandler;
                    params = match;
                    break;
                }
            }
        }

        // If no handler found, use the 404 handler
        if (!handler && this.routes['404']) {
            console.log("No handler found, using 404 handler");
            handler = this.routes['404'];
        }

        // Execute the handler
        if (handler) {
            try {
                console.log(`Executing handler for: ${path} with params:`, params);
                this.currentRoute = path;
                const content = await handler(params);
                console.log("Handler executed successfully");
                
                // Update only the content section, not the entire main element
                if (content && this.contentContainer) {
                    // Check if we're on the home page or product page
                    const isProductPage = path.includes('product.html');
                    console.log(`Is product page: ${isProductPage}`);
                    
                    // Find the appropriate content section to update
                    const contentSection = isProductPage 
                        ? this.contentContainer.querySelector('.product-details') 
                        : this.contentContainer.querySelector('.product-list');
                    
                    if (contentSection) {
                        console.log("Content section found, updating HTML");
                        contentSection.innerHTML = content;
                    } else {
                        console.log("Content section not found, creating structure");
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
                            console.log("Re-rendering categories");
                            renderCategories();
                        } else {
                            console.error("renderCategories function not found");
                        }
                    }
                } else {
                    console.error("No content or content container", { content, container: this.contentContainer });
                }
                
                // Emit route changed event
                console.log("Emitting routeChanged event");
                this.emit('routeChanged', { path, params });
                
            } catch (error) {
                console.error('Error handling route:', error);
                if (this.routes['error'] && this.contentContainer) {
                    const errorSection = this.contentContainer.querySelector('.product-list') || 
                                        this.contentContainer.querySelector('.product-details');
                    if (errorSection) {
                        console.log("Error section found, showing error");
                        errorSection.innerHTML = await this.routes['error'](error);
                    } else {
                        console.error("Error section not found");
                    }
                } else {
                    console.error("No error handler or content container");
                }
            }
        } else {
            console.error("No handler found for path:", path);
        }

        // Remove loading state
        if (this.contentContainer) {
            console.log("Removing loading class");
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