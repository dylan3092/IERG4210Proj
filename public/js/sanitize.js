/**
 * Comprehensive sanitization utilities for preventing XSS and other injection attacks
 */
const sanitize = {
    /**
     * Sanitize HTML content to prevent XSS attacks
     * @param {string} input - The input string to sanitize
     * @returns {string} Sanitized HTML string
     */
    html: function(input) {
        if (input === null || input === undefined) return '';
        const element = document.createElement('div');
        element.textContent = String(input);
        return element.innerHTML;
    },

    /**
     * Sanitize content for use in attributes
     * @param {string} input - The input string to sanitize
     * @returns {string} Sanitized attribute string
     */
    attribute: function(input) {
        if (input === null || input === undefined) return '';
        return String(input)
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    },

    /**
     * Sanitize content for use in JavaScript
     * @param {string} input - The input string to sanitize
     * @returns {string} Sanitized JavaScript string
     */
    script: function(input) {
        if (input === null || input === undefined) return '';
        return String(input)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/</g, '\\x3C')
            .replace(/>/g, '\\x3E')
            .replace(/\//g, '\\/');
    },

    /**
     * Sanitize URL to prevent javascript: and data: injections
     * @param {string} url - The URL to sanitize
     * @returns {string} Sanitized URL or empty string if dangerous
     */
    url: function(url) {
        if (!url) return '';
        
        // Convert to string and trim
        const sanitizedUrl = String(url).trim();
        
        // Check for javascript: or data: protocols (potential XSS vectors)
        if (/^(javascript|data|vbscript):/i.test(sanitizedUrl)) {
            return '';
        }
        
        // Basic URL encoding for extra safety
        return encodeURI(sanitizedUrl);
    },

    /**
     * Sanitize numeric input
     * @param {string|number} input - The input to sanitize
     * @param {number} defaultValue - Default value if input is invalid
     * @returns {number} Sanitized number
     */
    number: function(input, defaultValue = 0) {
        if (input === null || input === undefined) return defaultValue;
        const num = Number(input);
        return isNaN(num) ? defaultValue : num;
    },

    /**
     * Sanitize JSON to prevent prototype pollution
     * @param {string} json - JSON string to sanitize
     * @returns {Object} Parsed and sanitized object
     */
    json: function(json) {
        try {
            const parsed = JSON.parse(json);
            return this.recursiveSanitizeObject(parsed);
        } catch (e) {
            console.error('Error parsing JSON:', e);
            return {};
        }
    },

    /**
     * Recursively sanitize object properties
     * @param {Object} obj - Object to sanitize
     * @returns {Object} Sanitized object
     */
    recursiveSanitizeObject: function(obj) {
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }

        const result = Array.isArray(obj) ? [] : {};
        
        for (const key in obj) {
            // Skip prototype pollution attempts
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                continue;
            }
            
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                if (typeof obj[key] === 'object' && obj[key] !== null) {
                    result[key] = this.recursiveSanitizeObject(obj[key]);
                } else if (typeof obj[key] === 'string') {
                    result[key] = this.html(obj[key]);
                } else {
                    result[key] = obj[key];
                }
            }
        }
        
        return result;
    }
};

// Make sanitize available globally
window.sanitize = sanitize; 