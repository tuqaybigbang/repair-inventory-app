from flask import render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from app import app, db
from models import User, Item, ActivityLog, RepairRecord
import json
import os
from datetime import datetime
from openpyxl import Workbook
import io
import logging

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_activity(username, action, details=None, ip_address=None):
    """Helper function to log activities"""
    activity = ActivityLog(
        username=username,
        action=action,
        details=details,
        ip_address=ip_address or request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

@app.before_request
def load_logged_in_user():
    """Load the logged-in user before each request"""
    user_id = session.get('user_id')
    if user_id is None:
        session['user'] = None
    else:
        user = User.query.get(user_id)
        session['user'] = {
            'id': user.id,
            'username': user.username,
            'role': user.role
        } if user else None

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            session['user'] = {
                'id': user.id,
                'username': user.username,
                'role': user.role
            }
            log_activity(username, 'User logged in', ip_address=request.remote_addr)
            flash(f'Welcome, {user.username}!', 'success')
            
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    if session.get('user'):
        log_activity(session['user']['username'], 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Redirect to appropriate dashboard"""
    if not session.get('user'):
        return redirect(url_for('login'))
    
    if session['user']['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    items = Item.query
    
    if search:
        items = items.filter(
            db.or_(
                Item.name.contains(search),
                Item.item_type.contains(search),
                Item.manufacturer.contains(search),
                Item.model.contains(search),
                Item.notes.contains(search)
            )
        )
    
    items = items.all()
    users = User.query.all()
    
    # Get repair records with optional status filter
    repairs = RepairRecord.query
    if status_filter:
        repairs = repairs.filter(RepairRecord.status == status_filter)
    if search:
        repairs = repairs.filter(
            db.or_(
                RepairRecord.item_name.contains(search),
                RepairRecord.problem_description.contains(search),
                RepairRecord.repair_notes.contains(search)
            )
        )
    repairs = repairs.order_by(RepairRecord.received_date.desc()).all()
    
    return render_template('admin_dashboard.html', items=items, users=users, repairs=repairs, search=search, status_filter=status_filter)

@app.route('/user')
def user_dashboard():
    """User dashboard"""
    if not session.get('user'):
        return redirect(url_for('login'))
    
    username = session['user']['username']
    search = request.args.get('search', '')
    
    items = Item.query.filter(
        db.or_(
            Item.assigned_to == username,
            Item.assigned_to == 'public'
        )
    )
    
    if search:
        items = items.filter(
            db.or_(
                Item.name.contains(search),
                Item.item_type.contains(search),
                Item.manufacturer.contains(search),
                Item.model.contains(search),
                Item.notes.contains(search)
            )
        )
    
    items = items.all()
    
    # Get user's repair records
    repairs = RepairRecord.query.filter_by(user_id=session['user']['id']).order_by(RepairRecord.received_date.desc()).all()
    
    return render_template('user_dashboard.html', items=items, repairs=repairs, search=search)

@app.route('/item/<int:item_id>')
def item_detail(item_id):
    """Item detail view"""
    if not session.get('user'):
        return redirect(url_for('login'))
    
    item = Item.query.get_or_404(item_id)
    
    # Check access permissions
    if session['user']['role'] != 'admin':
        if item.assigned_to != session['user']['username'] and item.assigned_to != 'public':
            flash('Access denied.', 'error')
            return redirect(url_for('user_dashboard'))
    
    return render_template('item_detail.html', item=item)

@app.route('/admin/users')
def manage_users():
    """User management page"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
def create_user():
    """Create new user"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('manage_users'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('manage_users'))
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    
    log_activity(session['user']['username'], f'Created user: {username}')
    flash(f'User "{username}" created successfully.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/add_item', methods=['POST'])
def add_item():
    """Add new item"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    name = request.form.get('name', '').strip()
    quantity = request.form.get('quantity', 0)
    price = request.form.get('price', 0.0)
    item_type = request.form.get('item_type', '').strip()
    voltage = request.form.get('voltage', '').strip()
    model = request.form.get('model', '').strip()
    manufacturer = request.form.get('manufacturer', '').strip()
    notes = request.form.get('notes', '').strip()
    assigned_to = request.form.get('assigned_to', 'public')
    
    if not name:
        flash('Item name is required.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        quantity = int(quantity)
        price = float(price)
    except ValueError:
        flash('Invalid quantity or price format.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    item = Item(
        name=name,
        quantity=quantity,
        price=price,
        item_type=item_type,
        voltage=voltage,
        model=model,
        manufacturer=manufacturer,
        notes=notes,
        assigned_to=assigned_to
    )
    db.session.add(item)
    db.session.commit()
    
    log_activity(session['user']['username'], f'Added item: {name}')
    flash(f'Item "{name}" added successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_item/<int:item_id>', methods=['POST'])
def edit_item(item_id):
    """Edit existing item"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    item = Item.query.get_or_404(item_id)
    
    item.name = request.form.get('name', '').strip()
    item.quantity = int(request.form.get('quantity', 0))
    item.price = float(request.form.get('price', 0.0))
    item.item_type = request.form.get('item_type', '').strip()
    item.voltage = request.form.get('voltage', '').strip()
    item.model = request.form.get('model', '').strip()
    item.manufacturer = request.form.get('manufacturer', '').strip()
    item.notes = request.form.get('notes', '').strip()
    item.assigned_to = request.form.get('assigned_to', 'public')
    
    db.session.commit()
    
    log_activity(session['user']['username'], f'Edited item: {item.name}')
    flash(f'Item "{item.name}" updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    """Delete item"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    item = Item.query.get_or_404(item_id)
    item_name = item.name
    
    db.session.delete(item)
    db.session.commit()
    
    log_activity(session['user']['username'], f'Deleted item: {item_name}')
    flash(f'Item "{item_name}" deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/activity_log')
def activity_log():
    """View activity log"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('activity_log.html', logs=logs)

@app.route('/admin/export')
def export_excel():
    """Export items to Excel"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    items = Item.query.all()
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Electronic Components"
    
    # Headers
    headers = ['ID', 'Name', 'Type', 'Quantity', 'Price', 'Voltage', 'Model', 
               'Manufacturer', 'Notes', 'Assigned To', 'Created', 'Updated']
    ws.append(headers)
    
    # Data
    for item in items:
        ws.append([
            item.id,
            item.name,
            item.item_type or '',
            item.quantity,
            item.price,
            item.voltage or '',
            item.model or '',
            item.manufacturer or '',
            item.notes or '',
            item.assigned_to,
            item.created_at.strftime('%Y-%m-%d %H:%M'),
            item.updated_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    # Save to memory
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    log_activity(session['user']['username'], 'Exported items to Excel')
    
    response = make_response(output.read())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = f'attachment; filename=components_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response

# Repair Management Routes

@app.route('/admin/repairs')
def manage_repairs():
    """Admin repair management page"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    repairs = RepairRecord.query
    if status_filter:
        repairs = repairs.filter(RepairRecord.status == status_filter)
    if search:
        repairs = repairs.filter(
            db.or_(
                RepairRecord.item_name.contains(search),
                RepairRecord.problem_description.contains(search),
                RepairRecord.repair_notes.contains(search)
            )
        )
    repairs = repairs.order_by(RepairRecord.received_date.desc()).all()
    users = User.query.filter_by(role='user').all()
    
    return render_template('manage_repairs.html', repairs=repairs, users=users, search=search, status_filter=status_filter)

@app.route('/admin/create_repair', methods=['POST'])
def create_repair():
    """Create new repair record"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    item_name = request.form.get('item_name', '').strip()
    problem_description = request.form.get('problem_description', '').strip()
    repair_notes = request.form.get('repair_notes', '').strip()
    used_components = request.form.get('used_components', '').strip()
    
    if not user_id or not item_name or not problem_description:
        flash('User, item name, and problem description are required.', 'error')
        return redirect(url_for('manage_repairs'))
    
    # Handle file upload
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to filename to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_filename = filename
    
    repair = RepairRecord(
        user_id=user_id,
        item_name=item_name,
        problem_description=problem_description,
        repair_notes=repair_notes,
        used_components=used_components,
        image_filename=image_filename
    )
    db.session.add(repair)
    db.session.commit()
    
    log_activity(session['user']['username'], f'Created repair record for {item_name}')
    flash(f'Repair record for "{item_name}" created successfully.', 'success')
    return redirect(url_for('manage_repairs'))

@app.route('/admin/update_repair/<int:repair_id>', methods=['POST'])
def update_repair(repair_id):
    """Update repair record"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    repair = RepairRecord.query.get_or_404(repair_id)
    old_status = repair.status
    
    repair.item_name = request.form.get('item_name', '').strip()
    repair.problem_description = request.form.get('problem_description', '').strip()
    repair.repair_notes = request.form.get('repair_notes', '').strip()
    repair.used_components = request.form.get('used_components', '').strip()
    repair.status = request.form.get('status', 'In Progress')
    
    # Set completed date if status changed to Completed
    if repair.status == 'Completed' and old_status != 'Completed':
        repair.completed_date = datetime.utcnow()
    elif repair.status != 'Completed':
        repair.completed_date = None
    
    # Handle file upload
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            repair.image_filename = filename
    
    db.session.commit()
    
    log_activity(session['user']['username'], f'Updated repair record for {repair.item_name}')
    flash(f'Repair record updated successfully.', 'success')
    return redirect(url_for('manage_repairs'))

@app.route('/admin/delete_repair/<int:repair_id>', methods=['POST'])
def delete_repair(repair_id):
    """Delete repair record"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    repair = RepairRecord.query.get_or_404(repair_id)
    item_name = repair.item_name
    
    # Delete associated image file if exists
    if repair.image_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], repair.image_filename))
        except:
            pass
    
    db.session.delete(repair)
    db.session.commit()
    
    log_activity(session['user']['username'], f'Deleted repair record for {item_name}')
    flash(f'Repair record for "{item_name}" deleted successfully.', 'success')
    return redirect(url_for('manage_repairs'))

@app.route('/repair/<int:repair_id>')
def repair_detail(repair_id):
    """Repair detail view"""
    if not session.get('user'):
        return redirect(url_for('login'))
    
    repair = RepairRecord.query.get_or_404(repair_id)
    
    # Check access permissions
    if session['user']['role'] != 'admin' and repair.user_id != session['user']['id']:
        flash('Access denied.', 'error')
        return redirect(url_for('user_dashboard'))
    
    return render_template('repair_detail.html', repair=repair)

@app.route('/admin/export_repairs')
def export_repairs():
    """Export repair records to Excel"""
    if not session.get('user') or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    repairs = RepairRecord.query.order_by(RepairRecord.received_date.desc()).all()
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Repair Records"
    
    # Headers
    headers = ['ID', 'User', 'Item Name', 'Problem Description', 'Repair Notes', 
               'Used Components', 'Status', 'Received Date', 'Completed Date', 'Image']
    ws.append(headers)
    
    # Data
    for repair in repairs:
        ws.append([
            repair.id,
            repair.user.username,
            repair.item_name,
            repair.problem_description,
            repair.repair_notes or '',
            repair.used_components or '',
            repair.status,
            repair.received_date.strftime('%Y-%m-%d %H:%M'),
            repair.completed_date.strftime('%Y-%m-%d %H:%M') if repair.completed_date else '',
            repair.image_filename or ''
        ])
    
    # Save to memory
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    log_activity(session['user']['username'], 'Exported repair records to Excel')
    
    response = make_response(output.read())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = f'attachment; filename=repairs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    return response

@app.errorhandler(404)
def not_found(error):
    return render_template('login.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('index'))