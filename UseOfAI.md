## Use of AI Acknowledgement

**Student ID**: 1155175347

**Project Phase**: 1

**Date**: 2 Feb, 2025

## Acknowledgement


I acknowledge the use of [Perplexity] to generate code towards the completion of the project.


**(Note that the code in this example does not achieve what we expect.)**
## Transcript

**Prompt**: I want to create a dummy shopping
website from scratch by hardcoding the basic elements. (dummy means categories and products are only for the
purpose of displaying. Customers can not purchase goods at this moment.) Please guide me on how to do it. JavaScript is not necessary and do not have to be done right now. Front-end frameworks are allowed.

When I visit the webpage locally, I will be located in the main page. Left hand side contains a rectangular area, which is a list of categories. Clicking them will change the list of products displayed, that belongs to this category. The list of products should follow the CSS tableless, where number of items shown per row will change dynamically based on screen size. Clicking the thumbnail or the name of a product will redirect me to product page

HTML: Make good use of semantic HTML throughout the whole assign.
(<header>, <nav>, <footer>, <div>, <section>, <ul>, <li>...)

CSS: Clean separation of HTML, CSS and JS code and files throughout the whole assign. No inline CSS and JS are allowed No HTML for styling use, e.g. <center>, align="center", etc.

Main page demonstrates the use of “CSS tableless” product list.
Each product has at least its own thumbnail, name, price and addToCart button
(One approach is to use flexbox)
When the thumbnail or name is clicked, redirect to the corresponding product page. Product page contains full size image of the product, name of the product and price of the product, and description of the product. 

Below are some additional information:

Main page demonstrates the use of “CSS hover” shopping list. When displayed, it will cover any elements behind. Input boxes are used for inputting quantity of each selected product. Add a checkout button that will be used to submit the list to Payment Gateway. The shopping list is displayed in both main and product pages. When not hovering, show the total prices. When hovered (CSS hovering), expand it and show the details of each added items.

Product page provides product details. To show a full-size or bigger image, name, description, price, and addToCart button.

Both main and product pages should include a hierarchical navigation menu.
(e.g. Home or Home > Category1 or Home > Category1 > Product1)
They are hyperlinks that can redirect users to an upper level of the hierarchy


Please write me a HTML and a CSS file for this dummy shopping website so that I can run it locally

### Response
## index.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dummy Shopping - Home</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header>
    <nav>
      <!-- Hierarchical navigation: on the main page, only "Home" is shown -->
      <a href="index.html">Home</a>
    </nav>
  </header>

  <!-- Hover-based cart that appears in both main and product pages -->
  <section class="shopping-cart">
    <div class="cart-summary">
      <!-- Collapsed view showing total price -->
      <p>Total: $0.00</p>
    </div>
    <div class="cart-details">
      <!-- Expanded view on hover, showing details of items -->
      <h2>Shopping List</h2>
      <ul>
        <li>
          <!-- Example dummy items -->
          <span>Product 1</span>
          <input type="number" min="1" value="1">
          <span>$10.00</span>
        </li>
        <li>
          <span>Product 2</span>
          <input type="number" min="1" value="2">
          <span>$5.00</span>
        </li>
      </ul>
      <button type="submit">Checkout</button>
    </div>
  </section>

  <main>
    <!-- Left column: Categories list -->
    <aside>
      <h2>Categories</h2>
      <ul>
        <li><a href="?category=cat1">Category 1</a></li>
        <li><a href="?category=cat2">Category 2</a></li>
        <li><a href="?category=cat3">Category 3</a></li>
      </ul>
    </aside>

    <!-- Right column: Responsive product list (using CSS tableless approach) -->
    <section class="product-list">
      <article class="product-item">
        <a href="product.html?product=1">
          <img src="https://via.placeholder.com/150" alt="Product 1">
          <h3>Product 1</h3>
        </a>
        <p class="price">$10.00</p>
        <button>Add to Cart</button>
      </article>

      <article class="product-item">
        <a href="product.html?product=2">
          <img src="https://via.placeholder.com/150" alt="Product 2">
          <h3>Product 2</h3>
        </a>
        <p class="price">$15.00</p>
        <button>Add to Cart</button>
      </article>

      <article class="product-item">
        <a href="product.html?product=3">
          <img src="https://via.placeholder.com/150" alt="Product 3">
          <h3>Product 3</h3>
        </a>
        <p class="price">$20.00</p>
        <button>Add to Cart</button>
      </article>

      <article class="product-item">
        <a href="product.html?product=4">
          <img src="https://via.placeholder.com/150" alt="Product 4">
          <h3>Product 4</h3>
        </a>
        <p class="price">$25.00</p>
        <button>Add to Cart</button>
      </article>

      <article class="product-item">
        <a href="product.html?product=5">
          <img src="https://via.placeholder.com/150" alt="Product 5">
          <h3>Product 5</h3>
        </a>
        <p class="price">$30.00</p>
        <button>Add to Cart</button>
      </article>

      <article class="product-item">
        <a href="product.html?product=6">
          <img src="https://via.placeholder.com/150" alt="Product 6">
          <h3>Product 6</h3>
        </a>
        <p class="price">$35.00</p>
        <button>Add to Cart</button>
      </article>
    </section>
  </main>

  <footer>
    <p>© 2023 Dummy Shopping</p>
  </footer>
</body>
</html>
```

## product.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dummy Shopping - Product Details</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header>
    <nav>
      <!-- Hierarchical navigation: now showing Home > Category 1 > Product 1 as an example -->
      <a href="index.html">Home</a> &gt;
      <a href="index.html?category=cat1">Category 1</a> &gt;
      <span>Product 1</span>
    </nav>
  </header>

  <!-- Same cart hover feature as in main page -->
  <section class="shopping-cart">
    <div class="cart-summary">
      <p>Total: $0.00</p>
    </div>
    <div class="cart-details">
      <h2>Shopping List</h2>
      <ul>
        <li>
          <span>Product 1</span>
          <input type="number" min="1" value="1">
          <span>$10.00</span>
        </li>
      </ul>
      <button type="submit">Checkout</button>
    </div>
  </section>

  <main>
    <!-- Product details area, includes full-size image, name, description, price, etc. -->
    <section class="product-details">
      <img src="https://via.placeholder.com/400" alt="Product 1">
      <h1>Product 1</h1>
      <p class="price">$10.00</p>
      <p class="description">
        This is a dummy description for Product 1. 
        It provides more details than what's shown on the main page.
      </p>
      <button>Add to Cart</button>
    </section>
  </main>

  <footer>
    <p>© 2023 Dummy Shopping</p>
  </footer>
</body>
</html>
```

## styles.css
```css
/* Basic reset */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

/* Body styling */
body {
  font-family: Arial, sans-serif;
}

/* Header and navigation */
header {
  background-color: #ccc;
  padding: 1rem;
}

nav a {
  margin-right: 0.5rem;
  text-decoration: none;
  color: #000;
}

/* Main layout with categories aside and product listing */
main {
  display: flex;
  padding: 1rem;
}

/* Categories aside */
aside {
  width: 200px;
  margin-right: 1rem;
}

aside h2 {
  margin-bottom: 0.5rem;
}

aside ul {
  list-style-type: none;
}

aside li {
  margin-bottom: 0.5rem;
}

/* Responsive product list container (flex-based tableless) */
.product-list {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  flex: 1;
}

.product-item {
  width: 200px;
  border: 1px solid #eee;
  padding: 1rem;
  text-align: center;
}

.product-item img {
  max-width: 100%;
  height: auto;
}

.product-item .price {
  color: #f00;
  margin: 0.5rem 0;
}

/* Product details page layout */
.product-details {
  max-width: 600px;
  margin: 0 auto;
  text-align: center;
}

.product-details img {
  max-width: 100%;
  height: auto;
  margin-bottom: 1rem;
}

.product-details .price {
  color: #f00;
  font-size: 1.2rem;
  margin-bottom: 1rem;
}

.product-details .description {
  margin-bottom: 1rem;
}

/* Footer */
footer {
  background-color: #ccc;
  text-align: center;
  padding: 1rem;
  margin-top: 1rem;
}

/* Shopping cart hover */
.shopping-cart {
  position: fixed;
  top: 1rem;
  right: 1rem;
  width: 200px;
  background-color: #fff;
  border: 1px solid #999;
  z-index: 999; /* Allows the cart to cover elements behind it */
}

.cart-summary {
  padding: 0.5rem;
  background-color: #ddd;
  cursor: pointer;
}

.cart-details {
  display: none;
  padding: 0.5rem;
  border-top: 1px solid #999;
}

.shopping-cart:hover .cart-details {
  display: block;
}
```

---
来自 Perplexity 的回答: pplx.ai/share