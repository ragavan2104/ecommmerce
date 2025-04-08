import os
import sqlite3
from contextlib import closing
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime   
from functools import wraps
import json

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DATABASE = 'data/ecommerce.db'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    DATABASE=DATABASE,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH
)

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database Connection Manager
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    return db

def init_db():
    with closing(get_db()) as db:
        # Users table
        db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # Products table
        db.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL CHECK(price >= 0),
            image TEXT NOT NULL,
            rating REAL CHECK(rating BETWEEN 0 AND 5),
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )''')

        # User addresses table
        db.execute('''
        CREATE TABLE IF NOT EXISTS user_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            address_line1 TEXT NOT NULL,
            address_line2 TEXT,
            city TEXT NOT NULL,
            state TEXT NOT NULL,
            postal_code TEXT NOT NULL,
            country TEXT NOT NULL,
            is_default BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

        # Orders table
        db.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            address_id INTEGER NOT NULL,
            status TEXT DEFAULT 'processing',
            total_amount REAL NOT NULL,
            payment_method TEXT DEFAULT 'creditCard',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (address_id) REFERENCES user_addresses(id)
        )''')

        # Order items table
        db.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )''')

        # Create admin user if not exists
        if not db.execute('SELECT 1 FROM users WHERE username = "admin"').fetchone():
            admin_password = generate_password_hash('admin123')
            db.execute(
                'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                ('admin', admin_password, 'admin@example.com', 'admin')
            )
        
        db.commit()

def migrate_db():
    """Migrate existing database to add missing columns"""
    with closing(get_db()) as db:
        # Check if payment_method column exists in orders table
        cursor = db.execute("PRAGMA table_info(orders)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'payment_method' not in columns:
            db.execute('ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT "creditCard"')
            db.commit()
            print("Added payment_method column to orders table")

@app.route('/newsletter', methods=['POST'])
def newsletter():
    email = request.form.get('email')
    
    if not email:
        flash('Please enter a valid email address', 'danger')
        return redirect(url_for('home'))
    
    try:
        with closing(get_db()) as db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS newsletter_subscribers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            db.execute('''
                INSERT OR IGNORE INTO newsletter_subscribers (email)
                VALUES (?)
            ''', (email,))
            db.commit()
        
        flash('Thank you for subscribing to our newsletter!', 'success')
    except Exception as e:
        flash('Error subscribing to newsletter. Please try again.', 'danger')
    
    return redirect(url_for('home'))

# Initialize database
if not os.path.exists(DATABASE):
    init_db()
else:
    migrate_db()

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{timestamp}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return f"/static/uploads/{filename}"
    return None

def login_required(role='user'):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'username' not in session:
                flash('Please login first', 'danger')
                return redirect(url_for('login'))
            if role == 'admin' and session.get('role') != 'admin':
                flash('Admin access required', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Routes
@app.route('/')
def home():
    try:
        with closing(get_db()) as db:
            products = db.execute('''
                SELECT * FROM products 
                WHERE is_active = 1 
                ORDER BY created_at DESC 
                LIMIT 8
            ''').fetchall()
            
        return render_template('index.html', products=products)
    except sqlite3.OperationalError as e:
        flash('Database error. Please try again.', 'danger')
        return render_template('index.html', products=[])

@app.route('/products')
def products():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 8
        
        with closing(get_db()) as db:
            total = db.execute('SELECT COUNT(*) FROM products WHERE is_active = 1').fetchone()[0]
            offset = (page - 1) * per_page
            
            products = db.execute('''
                SELECT * FROM products 
                WHERE is_active = 1 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (per_page, offset)).fetchall()
            
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_prev': page > 1,
                'has_next': page * per_page < total,
                'prev_num': page - 1,
                'next_num': page + 1
            }
            
        return render_template('products.html', products=products, pagination=pagination)
    except sqlite3.OperationalError:
        flash('Database error. Please try again.', 'danger')
        return render_template('products.html', products=[], pagination=None)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    try:
        with closing(get_db()) as db:
            product = db.execute('''
                SELECT * FROM products 
                WHERE id = ? AND is_active = 1
            ''', (product_id,)).fetchone()
            
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('products'))
                
            related_products = db.execute('''
                SELECT * FROM products 
                WHERE category = ? AND id != ? AND is_active = 1
                LIMIT 4
            ''', (product['category'], product_id)).fetchall()
            
        return render_template('product_detail.html', 
                            product=product,
                            related_products=related_products)
    except sqlite3.OperationalError:
        flash('Database error. Please try again.', 'danger')
        return redirect(url_for('products'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        with closing(get_db()) as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session.update({
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role']
            })
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip().lower()

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        
        try:
            with closing(get_db()) as db:
                db.execute(
                    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                    (username, hashed_pw, email)
                )
                db.commit()
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')

    return render_template('register.html')

# Admin Routes
@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    with closing(get_db()) as db:
        products = db.execute('SELECT * FROM products ORDER BY created_at DESC').fetchall()
        users = db.execute('SELECT id, username, email, role FROM users').fetchall()
        orders = db.execute('''
            SELECT 
                orders.id, 
                users.username,
                users.email,
                user_addresses.full_name,
                user_addresses.phone,
                SUM(order_items.quantity) as total_quantity, 
                orders.status,
                orders.total_amount,
                orders.created_at,
                orders.payment_method
            FROM orders
            JOIN users ON orders.user_id = users.id
            JOIN user_addresses ON orders.address_id = user_addresses.id
            JOIN order_items ON orders.id = order_items.order_id
            GROUP BY orders.id
            ORDER BY orders.created_at DESC
        ''').fetchall()
    
    return render_template('admin_dashboard.html', 
                         products=products,
                         users=users,
                         orders=orders)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required(role='admin')
def add_product():
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file provided', 'danger')
            return redirect(request.url)

        file = request.files['image']
        image_url = save_uploaded_file(file)
        
        if not image_url:
            flash('Invalid file type', 'danger')
            return redirect(request.url)

        name = request.form.get('name', '').strip()
        price = request.form.get('price', 0)

        if not name:
            flash('Product name cannot be empty', 'danger')
            return redirect(request.url)

        try:
            price = float(price)
            if price <= 0:
                flash('Price must be greater than zero', 'danger')
                return redirect(request.url)

            with closing(get_db()) as db:
                db.execute(
                    '''INSERT INTO products 
                    (name, price, image, rating, category, description, is_active) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (
                        name,
                        price,
                        image_url,
                        float(request.form.get('rating', 0)),
                        request.form.get('category', '').strip(),
                        request.form.get('description', '').strip(),
                        1
                    )
                )
                db.commit()
            flash('Product added successfully! It is now visible on the main page.', 'success')
            return redirect(url_for('admin_dashboard'))
        except ValueError:
            flash('Invalid price or rating value', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('add_product.html')

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_product(product_id):
    with closing(get_db()) as db:
        product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        
        if not product:
            flash('Product not found', 'danger')
            return redirect(url_for('admin_dashboard'))
            
        if request.method == 'POST':
            image_url = product['image']
            if 'image' in request.files and request.files['image'].filename:
                file = request.files['image']
                new_image_url = save_uploaded_file(file)
                if new_image_url:
                    image_url = new_image_url
            
            try:
                db.execute('''
                    UPDATE products 
                    SET name = ?, price = ?, image = ?, rating = ?, 
                        category = ?, description = ?, is_active = ?
                    WHERE id = ?
                ''', (
                    request.form.get('name', product['name']).strip(),
                    float(request.form.get('price', product['price'])),
                    image_url,
                    float(request.form.get('rating', product['rating'])),
                    request.form.get('category', product['category']).strip(),
                    request.form.get('description', product['description']).strip(),
                    int(request.form.get('is_active', product['is_active'])),
                    product_id
                ))
                db.commit()
                flash('Product updated successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
            except ValueError:
                flash('Invalid price or rating value', 'danger')
            except Exception as e:
                flash(f'Error: {str(e)}', 'danger')
    
    return render_template('edit_product.html', product=product)

@app.route('/admin/users')
@login_required(role='admin')
def admin_users():
    with closing(get_db()) as db:
        users = db.execute('SELECT id, username, email, role, created_at FROM users').fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required(role='admin')
def edit_user(user_id):
    with closing(get_db()) as db:
        user = db.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
            
        if request.method == 'POST':
            new_role = request.form.get('role')
            new_email = request.form.get('email').strip().lower()
            
            try:
                db.execute('''
                    UPDATE users 
                    SET role = ?, email = ?
                    WHERE id = ?
                ''', (new_role, new_email, user_id))
                db.commit()
                flash('User updated successfully!', 'success')
                return redirect(url_for('admin_users'))
            except sqlite3.IntegrityError:
                flash('Email already exists', 'danger')
            except Exception as e:
                flash(f'Error: {str(e)}', 'danger')
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    if session.get('user_id') == user_id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))
        
    with closing(get_db()) as db:
        try:
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            db.commit()
            flash('User deleted successfully', 'success')
        except Exception as e:
            flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@login_required(role='admin')
def delete_product(product_id):
    with closing(get_db()) as db:
        result = db.execute('''
            UPDATE products 
            SET is_active = 0 
            WHERE id = ?
        ''', (product_id,))
        db.commit()

    if result.rowcount == 0:
        flash('Product not found', 'danger')
    else:
        flash('Product deactivated successfully. It will no longer appear on the main page.', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/products/activate/<int:product_id>', methods=['POST'])
@login_required(role='admin')
def activate_product(product_id):
    with closing(get_db()) as db:
        result = db.execute('''
            UPDATE products 
            SET is_active = 1 
            WHERE id = ?
        ''', (product_id,))
        db.commit()

    if result.rowcount == 0:
        flash('Product not found', 'danger')
    else:
        flash('Product activated successfully. It will now appear on the main page.', 'success')
    
    return redirect(url_for('admin_dashboard'))

# API Endpoints
@app.route('/api/products')
def api_products():
    with closing(get_db()) as db:
        products = db.execute('SELECT * FROM products WHERE is_active = 1').fetchall()
    return jsonify([dict(product) for product in products])

@app.route('/api/products/<int:product_id>')
def api_product(product_id):
    with closing(get_db()) as db:
        product = db.execute('SELECT * FROM products WHERE id = ? AND is_active = 1', (product_id,)).fetchone()
    return jsonify(dict(product)) if product else ('', 404)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    with closing(get_db()) as db:
        product = db.execute('SELECT * FROM products WHERE id = ? AND is_active = 1', (product_id,)).fetchone()
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']
    product_id_str = str(product_id)
    
    if product_id_str in cart:
        cart[product_id_str]['quantity'] += 1
    else:
        cart[product_id_str] = {
            'id': product['id'],
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }
    
    session['cart'] = cart
    session.modified = True
    
    return jsonify({
        'success': True,
        'message': 'Product added to cart',
        'cart_count': sum(item['quantity'] for item in cart.values())
    })

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    if 'cart' not in session:
        return jsonify({'success': False, 'message': 'Cart is empty'}), 400

    cart = session['cart']
    product_id_str = str(product_id)
    
    if product_id_str in cart:
        del cart[product_id_str]
        session['cart'] = cart
        session.modified = True
        return jsonify({
            'success': True,
            'message': 'Product removed from cart',
            'cart_count': sum(item['quantity'] for item in cart.values())
        })
    else:
        return jsonify({'success': False, 'message': 'Product not in cart'}), 404

@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    if 'cart' not in session:
        return jsonify({'success': False, 'message': 'Cart is empty'}), 400

    quantity = request.json.get('quantity', 1)
    if not isinstance(quantity, int) or quantity < 1:
        return jsonify({'success': False, 'message': 'Invalid quantity'}), 400

    cart = session['cart']
    product_id_str = str(product_id)
    
    if product_id_str in cart:
        cart[product_id_str]['quantity'] = quantity
        session['cart'] = cart
        session.modified = True
        return jsonify({
            'success': True,
            'message': 'Cart updated',
            'cart_count': sum(item['quantity'] for item in cart.values())
        })
    else:
        return jsonify({'success': False, 'message': 'Product not in cart'}), 404

@app.route('/get_cart', methods=['GET'])
def get_cart():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    cart = session.get('cart', {})
    cart_items = list(cart.values())
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    
    return jsonify({
        'success': True,
        'cart_items': cart_items,
        'cart_count': sum(item['quantity'] for item in cart_items),
        'total': total
    })

@app.route('/cart')
@login_required()
def view_cart():
    cart = session.get('cart', {})
    cart_items = list(cart.values())
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/checkout')
@login_required()
def checkout():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('view_cart'))
    
    with closing(get_db()) as db:
        user = db.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
        address = db.execute(
            'SELECT * FROM user_addresses WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()
        
        cart_items = []
        total = 0
        for product_id, item in session['cart'].items():
            product = db.execute(
                'SELECT id, name, price, image FROM products WHERE id = ? AND is_active = 1',
                (product_id,)
            ).fetchone()
            
            if product:
                item_total = product['price'] * item['quantity']
                cart_items.append({
                    'id': product['id'],
                    'name': product['name'],
                    'price': product['price'],
                    'image': product['image'],
                    'quantity': item['quantity'],
                    'item_total': item_total
                })
                total += item_total
    
    return render_template(
        'checkout.html',
        user=dict(user),
        address=dict(address) if address else None,
        cart_items=cart_items,
        total=total
    )

@app.route('/save_address', methods=['POST'])
@login_required()
def save_address():
    data = request.get_json()
    
    required_fields = ['full_name', 'phone', 'address_line1', 'city', 'state', 'postal_code', 'country']
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        with closing(get_db()) as db:
            existing = db.execute(
                'SELECT 1 FROM user_addresses WHERE user_id = ?',
                (session['user_id'],)
            ).fetchone()
            
            if existing:
                db.execute('''
                    UPDATE user_addresses SET
                        full_name = ?,
                        phone = ?,
                        address_line1 = ?,
                        address_line2 = ?,
                        city = ?,
                        state = ?,
                        postal_code = ?,
                        country = ?
                    WHERE user_id = ?
                ''', (
                    data['full_name'],
                    data['phone'],
                    data['address_line1'],
                    data.get('address_line2', ''),
                    data['city'],
                    data['state'],
                    data['postal_code'],
                    data['country'],
                    session['user_id']
                ))
            else:
                db.execute('''
                    INSERT INTO user_addresses (
                        user_id, full_name, phone, address_line1, address_line2,
                        city, state, postal_code, country
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['user_id'],
                    data['full_name'],
                    data['phone'],
                    data['address_line1'],
                    data.get('address_line2', ''),
                    data['city'],
                    data['state'],
                    data['postal_code'],
                    data['country']
                ))
            
            db.commit()
            return jsonify({'success': True, 'message': 'Address saved successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/place_order', methods=['POST'])
@login_required()
def place_order():
    if 'cart' not in session or not session['cart']:
        return jsonify({'success': False, 'message': 'Your cart is empty'}), 400
    
    try:
        data = request.get_json()
        payment_method = data.get('payment_method', 'creditCard')
        
        with closing(get_db()) as db:
            address = db.execute(
                'SELECT id FROM user_addresses WHERE user_id = ?',
                (session['user_id'],)
            ).fetchone()
            
            if not address:
                return jsonify({'success': False, 'message': 'Please provide shipping address'}), 400
            
            order_id = db.execute(
                'INSERT INTO orders (user_id, address_id, status, total_amount, payment_method) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], address['id'], 'processing', data.get('total'), payment_method)
            ).lastrowid
            
            for product_id, item in session['cart'].items():
                db.execute(
                    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                    (order_id, product_id, item['quantity'], item['price'])
                )
            
            db.commit()
            session.pop('cart', None)
            
            return jsonify({
                'success': True,
                'message': 'Order placed successfully',
                'order_id': order_id
            })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/orders')
@login_required()
def user_orders():
    with closing(get_db()) as db:
        orders = db.execute('''
            SELECT 
                orders.id, 
                orders.status, 
                orders.total_amount, 
                orders.created_at,
                user_addresses.full_name,
                user_addresses.city,
                user_addresses.state
            FROM orders
            JOIN user_addresses ON orders.address_id = user_addresses.id
            WHERE orders.user_id = ?
            ORDER BY orders.created_at DESC
        ''', (session['user_id'],)).fetchall()
        
        order_items = {}
        for order in orders:
            items = db.execute('''
                SELECT 
                    order_items.quantity,
                    order_items.price,
                    products.name,
                    products.image
                FROM order_items
                JOIN products ON order_items.product_id = products.id
                WHERE order_items.order_id = ?
            ''', (order['id'],)).fetchall()
            order_items[order['id']] = items
    
    return render_template('user_orders.html', 
                         orders=orders,
                         order_items=order_items)

@app.route('/admin/orders/<int:order_id>')
@login_required(role='admin')
def admin_order_detail(order_id):
    with closing(get_db()) as db:
        order = db.execute('''
            SELECT 
                orders.*,
                users.username,
                users.email,
                user_addresses.*
            FROM orders
            JOIN users ON orders.user_id = users.id
            JOIN user_addresses ON orders.address_id = user_addresses.id
            WHERE orders.id = ?
        ''', (order_id,)).fetchone()
        
        if not order:
            flash('Order not found', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        items = db.execute('''
            SELECT 
                order_items.quantity,
                order_items.price,
                products.name,
                products.image,
                products.id as product_id
            FROM order_items
            JOIN products ON order_items.product_id = products.id
            WHERE order_items.order_id = ?
        ''', (order_id,)).fetchall()
    
    return render_template('admin_order_detail.html',
                         order=order,
                         items=items)

@app.route('/admin/orders/<int:order_id>/update-status/<status>', methods=['POST'])
@login_required(role='admin')
def update_order_status(order_id, status):
    if status not in ['pending', 'completed', 'cancelled']:
        flash('Invalid status', 'danger')
        return redirect(url_for('admin_order_detail', order_id=order_id))
    
    try:
        with closing(get_db()) as db:
            order = db.execute('SELECT 1 FROM orders WHERE id = ?', (order_id,)).fetchone()
            if not order:
                flash('Order not found', 'danger')
                return redirect(url_for('admin_dashboard'))
            
            db.execute('''
                UPDATE orders
                SET status = ?
                WHERE id = ?
            ''', (status, order_id))
            db.commit()
        
        flash(f'Order status updated to {status}', 'success')
    except Exception as e:
        flash(f'Error updating order status: {str(e)}', 'danger')
    
    return redirect(url_for('admin_order_detail', order_id=order_id))

@app.route('/admin/orders/update_status/<int:order_id>', methods=['POST'])
@login_required(role='admin')
def update_order_status_legacy(order_id):
    new_status = request.form.get('status')
    
    if not new_status:
        flash('Status is required', 'danger')
        return redirect(url_for('admin_order_detail', order_id=order_id))
    
    try:
        with closing(get_db()) as db:
            db.execute('''
                UPDATE orders
                SET status = ?
                WHERE id = ?
            ''', (new_status, order_id))
            db.commit()
        
        flash('Order status updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating order status: {str(e)}', 'danger')
    
    return redirect(url_for('admin_order_detail', order_id=order_id))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def request_entity_too_large(e):
    flash('File too large (max 16MB)', 'danger')
    return redirect(request.referrer or url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)