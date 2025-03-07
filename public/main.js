document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOM Content Loaded');
    
    // Fetch categories
    try {
        console.log('Fetching categories...');
        const response = await fetch('http://s15.ierg4210.ie.cuhk.edu.hk:3000/api/categories');
        console.log('Categories response:', response);
        const categories = await response.json();
        console.log('Categories data:', categories);
        
        const categoriesList = document.querySelector('aside ul');
        categoriesList.innerHTML = categories.map(category => `
            <li><a href="?category=${category.catid}">${category.name}</a></li>
        `).join('');
    } catch (error) {
        console.error('Error fetching categories:', error);
    }

    // Fetch products
    try {
        console.log('Fetching products...');
        const response = await fetch('http://s15.ierg4210.ie.cuhk.edu.hk:3000/api/products');
        console.log('Products response:', response);
        const products = await response.json();
        console.log('Products data:', products);
        
        const productList = document.querySelector('.product-list');
        productList.innerHTML = products.map(product => {
            // Convert price to number and handle potential errors
            const price = parseFloat(product.price);
            const formattedPrice = !isNaN(price) ? price.toFixed(2) : '0.00';
            
            return `
                <article class="product-item">
                    <a href="product.html?product=${product.pid}">
                        <img src="${product.image ? 
                            'http://s15.ierg4210.ie.cuhk.edu.hk:3000/uploads/' + product.image : 
                            'images/default.jpg'}" 
                            alt="${product.name}" width="150" height="150">
                        <h3>${product.name}</h3>
                    </a>
                    <p class="price">$${formattedPrice}</p>
                    <button>Add to Cart</button>
                </article>
            `;
        }).join('');

    } catch (error) {
        console.error('Error fetching products:', error);
    }
});