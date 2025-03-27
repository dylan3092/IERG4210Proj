document.addEventListener('DOMContentLoaded', function() {
    // Get the breadcrumb navigation element
    const breadcrumb = document.querySelector('nav.breadcrumb');
    
    // Check if breadcrumb element exists
    if (!breadcrumb) {
        console.error('Breadcrumb navigation element not found');
        return;
    }

    // Get the current URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const category = urlParams.get('category');
    
    // Define category mapping
    const categoryMap = {
        'cat1': 'Category 1',
        'cat2': 'Category 2',
        'cat3': 'Category 3'
    };

    // If a category is selected, update the breadcrumb
    if (category && categoryMap[category]) {
        breadcrumb.innerHTML = `
            <a href="index.html">Home</a>
            <span class="separator">&gt;</span>
            <span class="current-category">${categoryMap[category]}</span>
        `;
    } else {
        breadcrumb.innerHTML = `<a href="index.html">Home</a>`;
    }
});
