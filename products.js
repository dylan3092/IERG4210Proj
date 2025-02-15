// Product data
const products = {
    '1': {
        name: 'Product 1',
        category: 'Category 1',
        price: 10.00,
        image: 'images/water.jpg',
        description: 'This is a detailed description of Product 1. It includes all the important features and specifications that a customer might want to know.'
    },
    '2': {
        name: 'Product 2',
        category: 'Category 1',
        price: 15.00,
        image: 'images/coke.jpg',
        description: 'This is a detailed description of Product 2. Here are all the features and specifications for this product.'
    },
    '3': {
        name: 'Product 3',
        category: 'Category 2',
        price: 20.00,
        image: 'images/fan.jpg',
        description: 'This is a detailed description of Product 3. Contains all important information about this product.'
    },
    '4': {
        name: 'Product 4',
        category: 'Category 2',
        price: 25.00,
        image: 'images/mouse.jpg',
        description: 'This is a detailed description of Product 4. All the important details about this product are listed here.'
    },
    '5': {
        name: 'Product 5',
        category: 'Category 3',
        price: 30.00,
        image: 'images/computer.jpg',
        description: 'This is a detailed description of Product 5. Find out everything you need to know about this product.'
    },
    '6': {
        name: 'Product 6',
        category: 'Category 3',
        price: 35.00,
        image: 'images/linux.jpg',
        description: 'This is a detailed description of Product 6. Comprehensive information about this product can be found here.'
    }
};

// Product page logic
document.addEventListener('DOMContentLoaded', function() {
    // Get the product ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('product');

    // Get the product data
    const product = products[productId];

    if (product) {
        // Update page title
        document.title = `${product.name} - Product Details`;

        // Update breadcrumb
        const breadcrumb = document.querySelector('nav.breadcrumb');
        breadcrumb.innerHTML = `
            <a href="index.html">Home</a>
            <span class="separator">&gt;</span>
            <a href="index.html?category=cat1">${product.category}</a>
            <span class="separator">&gt;</span>
            <span class="current-product">${product.name}</span>
        `;

        // Update product details
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = `
            <img src="${product.image}" alt="${product.name}" width="400" height="400">
            <div class="product-info">
                <h1>${product.name}</h1>
                <p class="category">${product.category}</p>
                <p class="price">$${product.price.toFixed(2)}</p>
                <p class="description">${product.description}</p>
                <button class="add-to-cart">Add to Cart</button>
            </div>
        `;
    } else {
        // Handle case when product is not found
        document.querySelector('main').innerHTML = '<p>Product not found</p>';
    }
});
