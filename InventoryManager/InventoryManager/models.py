from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_admin(self):
        return self.role == 'admin'

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    price = db.Column(db.Float, nullable=False, default=0.0)
    specifications = db.Column(db.Text)  # JSON string for flexible specs
    item_type = db.Column(db.String(50))  # e.g., 'resistor', 'capacitor', 'IC'
    voltage = db.Column(db.String(20))
    model = db.Column(db.String(100))
    manufacturer = db.Column(db.String(100))
    notes = db.Column(db.Text)
    assigned_to = db.Column(db.String(64), default='public')  # username or 'public'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Item {self.name}>'

class RepairRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_name = db.Column(db.String(200), nullable=False)
    problem_description = db.Column(db.Text, nullable=False)
    repair_notes = db.Column(db.Text)
    used_components = db.Column(db.Text)  # List of components used in repair
    status = db.Column(db.String(20), nullable=False, default='In Progress')  # 'In Progress' or 'Completed'
    received_date = db.Column(db.DateTime, default=datetime.utcnow)
    completed_date = db.Column(db.DateTime)
    image_filename = db.Column(db.String(255))  # Optional image upload
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to user
    user = db.relationship('User', backref=db.backref('repairs', lazy=True))
    
    def __repr__(self):
        return f'<RepairRecord {self.item_name} for {self.user.username}>'

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    
    def __repr__(self):
        return f'<ActivityLog {self.username}: {self.action}>'