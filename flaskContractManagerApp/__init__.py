import os
from os.path import dirname, abspath
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash



basedir = abspath(dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contracts.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOADED_DOCUMENTS_DEST'] = os.path.join(basedir, 'uploads')
app.config['UPLOADED_DOCUMENTS_ALLOW'] = set(['pdf', 'png', 'jpg', 'jpeg', 'gif'])

db = SQLAlchemy(app)

def create_first_user():
    from .models import User, Role
    user_role = Role.query.filter_by(name='user').first()
    manager_role = Role.query.filter_by(name='manager').first()
    financial_role = Role.query.filter_by(name='financial').first()
    if not User.query.first():
        # Create a role, if not already created, e.g., 'admin'
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        manager_role = Role.query.filter_by(name='manager').first()
        financial_role = Role.query.filter_by(name='financial').first()

        if not admin_role:
            admin_role = Role(name='admin')
            
            db.session.add(admin_role)
            db.session.commit()

        # Create the first user
        hashed_password = generate_password_hash('admin', method='sha256')
        first_user = User(username='admin', password=hashed_password, role_id=admin_role.id, role=admin_role)
        db.session.add(first_user)
        db.session.commit()
        print("First user created.")

def init_db():
    with app.app_context():
        db.create_all()
        db.session.commit()
        create_first_user()

init_db()

from . import models




