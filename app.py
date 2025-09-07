# backend/app.py
from datetime import datetime, timedelta
import os
import uuid

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'lms.sqlite')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-secret-key')  # change for production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# --------------------
# Models
# --------------------
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Employee')
    profile_name = db.Column(db.String(255))
    profile_phone = db.Column(db.String(50))
    profile_address = db.Column(db.Text)
    profile_photo = db.Column(db.Text)  # dataURL or path to upload
    reporting_officer_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_exp = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'profile': {
                'name': self.profile_name,
                'phone': self.profile_phone,
                'address': self.profile_address,
                'photo': self.profile_photo
            },
            'reportingOfficerId': self.reporting_officer_id
        }

class Leave(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100))
    days = db.Column(db.Integer)
    reason = db.Column(db.Text)
    status = db.Column(db.String(32), default='Pending')
    month = db.Column(db.String(10))
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, include_user=False):
        d = {
            'id': self.id,
            'userId': self.user_id,
            'type': self.type,
            'days': self.days,
            'reason': self.reason,
            'status': self.status,
            'month': self.month,
            'created': self.created.isoformat()
        }
        if include_user:
            u = User.query.get(self.user_id)
            d['email'] = u.email if u else None
        return d

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(100), nullable=False)
    perm = db.Column(db.String(100), nullable=False)

# --------------------
# Utilities
# --------------------
def this_month_key(dt=None):
    dt = dt or datetime.utcnow()
    return f"{dt.year}-{dt.month:02d}"

def seed_defaults():
    # Create default roles/permissions and demo users if empty
    if User.query.count() == 0:
        admin = User(email='admin@demo.com', password_hash=generate_password_hash('Admin@123'), role='Admin', profile_name='Admin')
        hr    = User(email='hr@demo.com',    password_hash=generate_password_hash('Hr@12345'), role='HR', profile_name='HR')
        emp   = User(email='emp@demo.com',   password_hash=generate_password_hash('Emp@12345'), role='Employee', profile_name='Employee')
        db.session.add_all([admin, hr, emp])
        db.session.commit()

    if Permission.query.count() == 0:
        defaults = {
            'Admin':   ['approve_leave','assign_reporting','manage_permissions','view_dashboard','apply_leave','manage_users'],
            'HR':      ['approve_leave','assign_reporting','view_dashboard','apply_leave'],
            'Finance': ['view_dashboard'],
            'IT':      ['view_dashboard'],
            'Teacher': ['apply_leave','view_dashboard'],
            'Employee':['apply_leave','view_dashboard']
        }
        for r,p_list in defaults.items():
            for p in p_list:
                db.session.add(Permission(role=r, perm=p))
        db.session.commit()

def has_perm(role, perm):
    return Permission.query.filter_by(role=role, perm=perm).first() is not None

# --------------------
# Auth endpoints
# --------------------
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role = data.get('role') or 'Employee'
    if not email or not password or len(password) < 8:
        return jsonify({'ok': False, 'msg': 'Invalid email/password'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'ok': False, 'msg': 'Email already registered'}), 400
    u = User(email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(u); db.session.commit()
    return jsonify({'ok': True, 'msg': 'Account created'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({'ok': False, 'msg': 'Invalid credentials'}), 401
    token = create_access_token(identity=u.id)
    return jsonify({'ok': True, 'access_token': token, 'user': u.to_dict()})

@app.route('/api/forgot', methods=['POST'])
def forgot():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    u = User.query.filter_by(email=email).first()
    if not u:
        return jsonify({'ok': False, 'msg': 'No account found'}), 404
    token = str(uuid.uuid4())
    u.reset_token = token
    u.reset_token_exp = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()
    # In demo: return token in response. In real app: send by email.
    return jsonify({'ok': True, 'reset_token': token})

@app.route('/api/reset', methods=['POST'])
def reset():
    data = request.get_json() or {}
    token = data.get('token')
    new_password = data.get('password')
    if not token or not new_password or len(new_password) < 8:
        return jsonify({'ok': False, 'msg': 'Invalid token or password'}), 400
    u = User.query.filter_by(reset_token=token).first()
    if not u or not u.reset_token_exp or datetime.utcnow() > u.reset_token_exp:
        return jsonify({'ok': False, 'msg': 'Invalid or expired token'}), 400
    u.password_hash = generate_password_hash(new_password)
    u.reset_token = None
    u.reset_token_exp = None
    db.session.commit()
    return jsonify({'ok': True, 'msg': 'Password updated'})

# --------------------
# User/profile
# --------------------
@app.route('/api/me', methods=['GET'])
@jwt_required()
def me():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u: return jsonify({'ok': False}), 404
    return jsonify({'ok': True, 'user': u.to_dict()})

@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    uid = get_jwt_identity()
    data = request.get_json() or {}
    u = User.query.get(uid)
    if not u: return jsonify({'ok': False}), 404
    u.profile_name = data.get('name')
    u.profile_phone = data.get('phone')
    u.profile_address = data.get('address')
    u.profile_photo = data.get('photo')  # frontend can send dataURL
    db.session.commit()
    return jsonify({'ok': True, 'user': u.to_dict()})

# --------------------
# Leaves
# --------------------
@app.route('/api/leaves', methods=['POST'])
@jwt_required()
def create_leave():
    uid = get_jwt_identity()
    data = request.get_json() or {}
    ltype = data.get('type')
    days = int(data.get('days') or 0)
    reason = data.get('reason') or ''
    if not ltype or days <= 0:
        return jsonify({'ok': False, 'msg': 'Invalid data'}), 400
    month = this_month_key()
    leave = Leave(user_id=uid, type=ltype, days=days, reason=reason, status='Pending', month=month)
    # Emergency -> auto-approve
    if ltype == 'Emergency':
        leave.status = 'Approved'
    db.session.add(leave)
    db.session.commit()
    return jsonify({'ok': True, 'leave': leave.to_dict(include_user=True)})

@app.route('/api/leaves', methods=['GET'])
@jwt_required()
def list_leaves():
    uid = get_jwt_identity()
    # optional query ?all=true for admins/HR
    show_all = request.args.get('all') == 'true'
    user = User.query.get(uid)
    if show_all and user and has_perm(user.role, 'approve_leave'):
        leaves = Leave.query.order_by(Leave.created.desc()).all()
    else:
        leaves = Leave.query.filter_by(user_id=uid).order_by(Leave.created.desc()).all()
    return jsonify({'ok': True, 'leaves': [l.to_dict(include_user=True) for l in leaves]})

@app.route('/api/leaves/<leave_id>', methods=['PUT'])
@jwt_required()
def update_leave(leave_id):
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user or not has_perm(user.role, 'approve_leave'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    data = request.get_json() or {}
    action = data.get('action')
    l = Leave.query.get(leave_id)
    if not l: return jsonify({'ok': False, 'msg': 'Not found'}), 404
    if action == 'approve':
        l.status = 'Approved'
    elif action == 'reject':
        l.status = 'Rejected'
    else:
        return jsonify({'ok': False, 'msg': 'Unknown action'}), 400
    db.session.commit()
    return jsonify({'ok': True, 'leave': l.to_dict(include_user=True)})

# --------------------
# Admin / Users / Permissions
# --------------------
@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u or not has_perm(u.role, 'manage_users'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    users = User.query.order_by(User.email).all()
    return jsonify({'ok': True, 'users': [usr.to_dict() for usr in users]})

@app.route('/api/users/<user_id>', methods=['PUT'])
@jwt_required()
def change_user(user_id):
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u or not has_perm(u.role, 'manage_users'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    target = User.query.get(user_id)
    if not target: return jsonify({'ok': False, 'msg': 'Not found'}), 404
    data = request.get_json() or {}
    role = data.get('role')
    if role:
        target.role = role
    db.session.commit()
    return jsonify({'ok': True, 'user': target.to_dict()})

@app.route('/api/users/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u or not has_perm(u.role, 'manage_users'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    if user_id == uid:
        return jsonify({'ok': False, 'msg': 'Cannot delete yourself'}), 400
    target = User.query.get(user_id)
    if not target: return jsonify({'ok': False, 'msg': 'Not found'}), 404
    db.session.delete(target)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/permissions', methods=['GET'])
@jwt_required()
def list_perms():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u or not has_perm(u.role, 'manage_permissions'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    perms = Permission.query.all()
    # group by role
    out = {}
    for p in perms:
        out.setdefault(p.role, []).append(p.perm)
    return jsonify({'ok': True, 'perms': out})

@app.route('/api/permissions', methods=['PUT'])
@jwt_required()
def save_perms():
    uid = get_jwt_identity()
    u = User.query.get(uid)
    if not u or not has_perm(u.role, 'manage_permissions'):
        return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
    data = request.get_json() or {}
    perms = data.get('perms') or {}
    Permission.query.delete()
    for r, p_list in perms.items():
        for p in p_list:
            db.session.add(Permission(role=r, perm=p))
    db.session.commit()
    return jsonify({'ok': True})

# --------------------
# Reporting officers (assign)
# --------------------
@app.route('/api/reporting', methods=['GET', 'PUT'])
@jwt_required()
def reporting():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if request.method == 'GET':
        if not user or not has_perm(user.role, 'assign_reporting'):
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        users = User.query.all()
        return jsonify({'ok': True, 'users': [u.to_dict() for u in users]})
    else:
        if not user or not has_perm(user.role, 'assign_reporting'):
            return jsonify({'ok': False, 'msg': 'Forbidden'}), 403
        data = request.get_json() or {}
        assignments = data.get('assignments') or {}  # { user_id: ro_id, ... }
        for uid_k, ro_id in assignments.items():
            u = User.query.get(uid_k)
            if u:
                u.reporting_officer_id = ro_id or None
        db.session.commit()
        return jsonify({'ok': True})

# --------------------
# Serve frontend (optional)
# --------------------
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    # If a static file exists in frontend folder, let flask serve it (so you can open http://localhost:5000)
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# --------------------
# Boot
# --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_defaults()
    app.run(debug=True, host='0.0.0.0', port=5000)
