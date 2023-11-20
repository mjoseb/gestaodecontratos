from flaskContractManagerApp import db
from flask_login import UserMixin

def create_first_user():
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



contract_manager = db.Table('contract_manager',
    db.Column('contract_id', db.Integer, db.ForeignKey('contract.id'), primary_key=True),
    db.Column('manager_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

contract_auditor = db.Table('contract_auditor',
    db.Column('contract_id', db.Integer, db.ForeignKey('contract.id'), primary_key=True),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id'), primary_key=True))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', back_populates='users')
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=True)  
    contact_info = db.Column(db.String(100), nullable=True)
    position = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(50), nullable=True)






class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    initial_balance = db.Column(db.Float, nullable=False) 
    document = db.Column(db.String(255), nullable=True)    
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'), nullable=False)
    managers = db.relationship("User", secondary=contract_manager, backref=db.backref('contracts_managed', lazy='dynamic'))
    auditors = db.relationship("User", secondary=contract_auditor, backref=db.backref('contracts_audited', lazy='dynamic'))
    supplier = db.relationship("Supplier")        
    contract_number = db.Column(db.String(100), nullable=False)
    original_process = db.Column(db.Integer, nullable=False)    
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'), nullable=False)
    author = db.relationship('Author', backref='contracts')
    origin_id = db.Column(db.Integer, db.ForeignKey('origin.id'), nullable=False)
    origin = db.relationship('Origin', backref='contracts')
    procedure_id = db.Column(db.Integer, db.ForeignKey('procedure.id'), nullable=False)
    procedure = db.relationship('Procedure', backref='contracts')
    classification_id = db.Column(db.Integer, db.ForeignKey('classification.id'), nullable=False)
    classification = db.relationship('Classification', backref='contracts')
    sector_id = db.Column(db.Integer, db.ForeignKey('sector.id'), nullable=False)
    sector = db.relationship('Sector', backref='contracts')
    directorate_id = db.Column(db.Integer, db.ForeignKey('directorate.id'), nullable=False)
    directorate = db.relationship('Directorate', backref='contracts')
    instrument_id = db.Column(db.Integer, db.ForeignKey('instrument.id'), nullable=False)
    instrument = db.relationship('Instrument', backref='contracts')
    last_update_id = db.Column(db.Integer, db.ForeignKey('last_update.id'), nullable=False)
    last_update = db.relationship('LastUpdate', backref='contracts')
    update_date = db.Column(db.Date, nullable=False)
    update_protocol = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    monthly_value = db.Column(db.Float, nullable=False)
    total_value = db.Column(db.Float, nullable=False)



class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Origin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Procedure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Classification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Sector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    directorate_id = db.Column(db.Integer, db.ForeignKey('directorate.id'), nullable=False)
    directorate = db.relationship('Directorate', backref=db.backref('sectors', lazy=True))


class Directorate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Instrument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class LastUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)


class ContractAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'), nullable=False)
    contract = db.relationship('Contract', backref=db.backref('audits', lazy=True))
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    audit_type = db.Column(db.String(100), nullable=False)  # Added audit type column
    notes = db.Column(db.Text, nullable=True)
    attachment = db.Column(db.String(255), nullable=True)



class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    cnpj = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(100), nullable=False)




class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    users = db.relationship('User', back_populates='role')

class DocumentTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)