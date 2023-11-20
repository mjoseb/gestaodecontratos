import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, String, ForeignKey, or_, func
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from flask_uploads import UploadSet, configure_uploads, IMAGES, DOCUMENTS
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from os.path import dirname, abspath
from datetime import date, datetime, time
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from flask_mail import Mail, Message
from datetime import timedelta
import logging
import traceback
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Length
from flask import request, jsonify
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO
from jinja2 import Environment



basedir = abspath(dirname(__file__))

#from models import User, Contrato, Supplier, Employee


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contratos.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOADED_DOCUMENTS_DEST'] = os.path.join(basedir, 'uploads')
app.config['UPLOADED_DOCUMENTS_ALLOW'] = set(['pdf', 'png', 'jpg', 'jpeg', 'gif'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
documents = UploadSet('documents', DOCUMENTS + IMAGES)
app.config['UPLOADED_DOCUMENTS_DEST'] = 'uploads'
configure_uploads(app, documents)
admin = Admin(app, name='Administração', template_mode='bootstrap3')


app.config.update(
    MAIL_SERVER='expresso.pr.gov.br',
    MAIL_PORT=465,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='marcosbernardes',
    MAIL_PASSWORD='Computador01',
)
mail = Mail(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


contrato_manager = db.Table('contrato_manager',
    db.Column('contrato_id', db.Integer, db.ForeignKey('contrato.id'), primary_key=True),
    db.Column('manager_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

contrato_auditor = db.Table('contrato_auditor',
    db.Column('contrato_id', db.Integer, db.ForeignKey('contrato.id'), primary_key=True),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


def format_date(value, date_format='%d/%m/%y'):
    if value is None:
        return ""
    return value.strftime(date_format)


app.jinja_env.filters['format_date'] = format_date





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

class Contrato(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    initial_balance = db.Column(db.Float, nullable=False)
    document = db.Column(db.String(255), nullable=True)    
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'), nullable=False)
    managers = db.relationship("User", secondary=contrato_manager, backref=db.backref('contratos_managed', lazy='dynamic'))
    auditors = db.relationship("User", secondary=contrato_auditor, backref=db.backref('contratos_audited', lazy='dynamic'))
    supplier = db.relationship("Supplier")        
    contrato_number = db.Column(db.String(100), unique=True, nullable=False)
    original_process = db.Column(db.Integer, nullable=False)    
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'), nullable=False)
    author = db.relationship('Author', backref='contratos')
    origin_id = db.Column(db.Integer, db.ForeignKey('origin.id'), nullable=False)
    origin = db.relationship('Origin', backref='contratos')
    procedimento_id = db.Column(db.Integer, db.ForeignKey('procedimento.id'), nullable=False)
    procedimento = db.relationship('Procedimento', backref='contratos')
    classification_id = db.Column(db.Integer, db.ForeignKey('classification.id'), nullable=False)
    classification = db.relationship('Classification', backref='contratos')
    sector_id = db.Column(db.Integer, db.ForeignKey('sector.id'), nullable=False)
    sector = db.relationship('Sector', backref='contratos')
    directorate_id = db.Column(db.Integer, db.ForeignKey('directorate.id'), nullable=False)
    directorate = db.relationship('Directorate', backref='contratos')
    instrument_id = db.Column(db.Integer, db.ForeignKey('instrument.id'), nullable=False)
    instrument = db.relationship('Instrument', backref='contratos')
    last_update_id = db.Column(db.Integer, db.ForeignKey('last_update.id'), nullable=False)
    last_update = db.relationship('LastUpdate', backref='contratos')
    update_date = db.Column(db.Date, nullable=False)
    update_protocol = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    monthly_value = db.Column(db.Float, nullable=False)
    total_value = db.Column(db.Float, nullable=False)
    financial_commitments = db.relationship('FinancialCommitment', backref='contrato', lazy=True)
    debits = db.relationship('Debit', backref='contrato', lazy=True)

    def debit(self, value, month, year):
        if self.balance - value >= 0:
            self.balance -= value
            new_debit = Debit(value=value, month=month, year=year, contrato_id=self.id)
            db.session.add(new_debit)
            db.session.commit()
        else:
            raise ValueError("Saldo insuficiente para realizar o débito.")




class ItemDocumentoFiscalizacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)
    contrato=db.relationship('Contrato', backref='itens')
    codigo_item = db.Column(db.String(50), nullable=False)
    clausula = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.String(100), nullable=False)
    

class ItemObservacaoMensal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_documento_id = db.Column(db.Integer, db.ForeignKey('item_documento_fiscalizacao.id'), nullable=False)
    observacao = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="Não Atendido")
    mes = db.Column(db.Integer, nullable=False)
    ano = db.Column(db.Integer, nullable=False)
    
    item_documento = db.relationship('ItemDocumentoFiscalizacao', backref='observacoes_mensais')

class ItemObservacoesGerais(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)
    contrato=db.relationship('Contrato', backref='itens_gerais')
    observacoes_gerais = db.Column(db.String(100), nullable=True)    
    mes = db.Column(db.Integer, nullable=False)
    ano = db.Column(db.Integer, nullable=False)

class Debit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Float, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)

class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Origin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Procedimento(db.Model):
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


class ContratoAudit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)
    contrato = db.relationship('Contrato', backref=db.backref('audits', lazy=True))
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    audit_type = db.Column(db.String(100), nullable=False)  # Added audit type column
    notes = db.Column(db.Text, nullable=True)
    attachment = db.Column(db.String(255), nullable=True)


class ContratoTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    columns = db.relationship('ContratoTableColumn', backref='contrato_table', lazy=True)


class ContratoTableColumn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('contrato_table.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    data_type = db.Column(db.String(50), nullable=False)



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


class FinancialCommitment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_code = db.Column(db.String(8), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Float, nullable=False)
    contrato_id = db.Column(db.Integer, db.ForeignKey('contrato.id'), nullable=False)

class BudgetAllocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_code = db.Column(db.String(8), nullable=False)
    value = db.Column(db.Float, nullable=False)


class FinancialCommitmentForm(FlaskForm):
    contrato_id = IntegerField("ID do Contrato", validators=[DataRequired()])
    expense_code = StringField("Código Natureza da Despesa", validators=[DataRequired(), Length(min=8, max=8)])
    title = StringField("Título", validators=[DataRequired()])
    value = FloatField("Valor", validators=[DataRequired()])
    submit = SubmitField("Salvar Empenho")


class BudgetAllocationForm(FlaskForm):
    expense_code = StringField("Expense Code", validators=[DataRequired(), Length(min=8, max=8)])
    value = FloatField("Value", validators=[DataRequired()])
    submit = SubmitField("Add Budget Allocation")

def insert_budget_allocation(expense_code, value):
    budget_allocation = BudgetAllocation(expense_code=expense_code, value=value)
    db.session.add(budget_allocation)
    db.session.commit()



def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role.name not in roles:  # Compare role names instead of instances
                flash("Você não tem permissão para acessar esta página.")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator



def contrato_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        contrato_id = kwargs.get('contrato_id', None)
        if contrato_id:
            contrato = Contrato.query.get(contrato_id)
            is_manager = any(user.id == current_user.id for user in contrato.managers)
            is_auditor = any(user.id == current_user.id for user in contrato.auditors)
            if not (contrato and (is_manager or is_auditor or current_user.role.name == 'admin')):
                return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return decorated_function

class AuthenticatedModelView(ModelView):

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


class ItemDocumentoFiscalizacaoView(AuthenticatedModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'contrato_id', 'contrato', 'clausula', 'descricao')


class ItemObservacaoMensalView(AuthenticatedModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'item_documento_id', 'observacao', 'status', 'mes', 'ano', 'item_documento')

# Agora, use AuthenticatedModelView em vez de ModelView:
admin.add_view(AuthenticatedModelView(Contrato, db.session))
admin.add_view(ItemDocumentoFiscalizacaoView(ItemDocumentoFiscalizacao, db.session))
admin.add_view(ItemObservacaoMensalView(ItemObservacaoMensal, db.session))
admin.add_view(AuthenticatedModelView(Debit, db.session))
admin.add_view(AuthenticatedModelView(Author, db.session))
admin.add_view(AuthenticatedModelView(Origin, db.session))
admin.add_view(AuthenticatedModelView(Procedimento, db.session))
admin.add_view(AuthenticatedModelView(Classification, db.session))
admin.add_view(AuthenticatedModelView(Sector, db.session))
admin.add_view(AuthenticatedModelView(Directorate, db.session))
admin.add_view(AuthenticatedModelView(Instrument, db.session))
admin.add_view(AuthenticatedModelView(LastUpdate, db.session))
admin.add_view(AuthenticatedModelView(ContratoAudit, db.session))
admin.add_view(AuthenticatedModelView(ContratoTable, db.session))
admin.add_view(AuthenticatedModelView(ContratoTableColumn, db.session))
admin.add_view(AuthenticatedModelView(Supplier, db.session))
admin.add_view(AuthenticatedModelView(Role, db.session))
admin.add_view(AuthenticatedModelView(DocumentTemplate, db.session))
admin.add_view(AuthenticatedModelView(FinancialCommitment, db.session))
admin.add_view(AuthenticatedModelView(BudgetAllocation, db.session))






@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html'), 403



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
        hashed_password = generate_password_hash('admin')
        first_user = User(username='admin', password=hashed_password, role_id=admin_role.id, role=admin_role)
        db.session.add(first_user)
        db.session.commit()
        print("First user created.")



# Routes



@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    contratos = Contrato.query.all()
    today = date.today()

    managers = User.query.all()
    directorates = Directorate.query.all()
    auditors = User.query.all()
    sectors = Sector.query.all()

    contratos_list = []
    for contrato in contratos:
        date_obj = datetime.combine(contrato.end_date, time())
        remaining_days = (date_obj.date() - today).days
        contratos_list.append((contrato, remaining_days))

    contratos_less_than_90_days = sum(1 for _, remaining_days in contratos_list if remaining_days <= 90)
    contratos_less_than_120_days = sum(1 for _, remaining_days in contratos_list if 90 < remaining_days <= 120)
    contratos_less_than_180_days = sum(1 for _, remaining_days in contratos_list if 120 < remaining_days <= 180)
    contratos_more_than_180_days = sum(1 for _, remaining_days in contratos_list if remaining_days > 180)

    return render_template('dashboard.html', contratos=contratos_list, managers=managers, sectors=sectors, directorates=directorates, auditors=auditors, contratos_less_than_90_days=contratos_less_than_90_days, contratos_less_than_120_days=contratos_less_than_120_days, contratos_less_than_180_days=contratos_less_than_180_days, contratos_more_than_180_days=contratos_more_than_180_days)



@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # Adicione esta linha
        name = request.form['name']
        contact_info = request.form['contact_info']
        position = request.form['position']
        department = request.form['department']
        role_id = request.form['role_id']

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password, email=email, name=name, contact_info=contact_info,
                        position=position, department=department, role_id=role_id)

        db.session.add(new_user)
        db.session.commit()

        flash('Usuário criado com sucesso!', category='success')
        return redirect(url_for('dashboard'))

    roles = Role.query.all()
    return render_template('create_user.html', roles=roles)





# TODO: Adicione as rotas e funções para gerenciar contratos, fornecedores e funcionários.
# Não se esqueça de aplicar a autenticação e autorização apropriadas conforme mencionado nos requisitos.






# Contratos


from sqlalchemy import or_

def apply_filters(base_query, search_query, sector_filter, days_filter, directorate_filter, manager_filter, auditor_filter):
    if search_query:
        search_term = f'%{search_query}%'
        base_query = base_query.filter(Contrato.title.ilike(search_term))

    if days_filter > 0:
        min_date = date.today() + timedelta(days=days_filter)
        base_query = base_query.filter(Contrato.end_date <= min_date)

    if directorate_filter:
        base_query = base_query.filter(Contrato.directorate_id == int(directorate_filter))

    if sector_filter:
        base_query = base_query.filter(Contrato.sector_id == int(sector_filter))

    if manager_filter:
        search_manager = f'{manager_filter}%'
        base_query = base_query.filter(Contrato.managers.any(User.id.cast(String).ilike(search_manager)))

    if auditor_filter:
        search_auditor = f'{auditor_filter}%'
        base_query = base_query.filter(Contrato.auditors.any(User.id.cast(String).ilike(search_auditor)))

    return base_query



@app.route('/contratos', methods=['GET', 'POST'])
@login_required
def contratos():
    search_query = request.args.get('search', '')
    days_filter = (request.args.get('days_filter', 0))
    if days_filter:
        days_filter = int(days_filter)
    else:
        days_filter = 0
    directorate_filter = request.args.get('directorates', '')
    sector_filter = request.args.get('sectors', '')
    manager_filter = request.args.get('manager', '')
    auditor_filter = request.args.get('auditor', '')

    # Carregue os dados para managers, directorates e auditors aqui
    managers = User.query.all()
    directorates = Directorate.query.all()
    auditors = User.query.all()
    sectors = Sector.query.all()

    base_query = Contrato.query

    if current_user.role.name != "admin":
        base_query = base_query.filter(
            or_(
                Contrato.managers.any(User.id == current_user.id),
                Contrato.auditors.any(User.id == current_user.id)
            )
        )

    filtered_query = apply_filters(base_query, search_query, sector_filter, days_filter, directorate_filter, manager_filter, auditor_filter)
    contratos = filtered_query.all()

    today = date.today()

    contratos_list = []
    for contrato in contratos:
        date_obj = datetime.combine(contrato.end_date, time())
        remaining_days = (date_obj.date() - today).days
        contratos_list.append((contrato, remaining_days))

    print("Sectors:", sectors)
    # Passe as variáveis managers, directorates e auditors para o template
    return render_template('contratos.html', contratos=contratos_list, managers=managers, sectors=sectors, directorates=directorates, auditors=auditors)




@app.route('/relatorio_contrato/<int:contrato_id>', methods=['GET', 'POST'])
@login_required
def relatorio_contrato(contrato_id):
    contrato = Contrato.query.get(contrato_id)
    if not contrato:
        flash('Contrato não encontrado!', category='error')
        return redirect(url_for('dashboard'))
    
    itens = ItemDocumentoFiscalizacao.query.filter_by(contrato_id=contrato_id).all()

    if request.method == 'POST':
        mes = int(request.form.get('mes'))
        ano = int(request.form.get('ano'))
        
        for item in itens:
            observacao = request.form.get(f'observacao_{item.id}')
            status = request.form.get(f'status_{item.id}')
            new_observacao = ItemObservacaoMensal(
                item_documento_id=item.id,
                observacao=observacao,
                status=status,
                mes=mes,
                ano=ano
            )
            db.session.add(new_observacao)
        db.session.commit()
        flash('Relatório salvo com sucesso!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('relatorio_contrato.html', contrato=contrato, itens=itens)



# TODO: Adicione rotas e funções para adicionar, editar e excluir contratos

# Fornecedores
@app.route('/suppliers')
@login_required
@role_required('admin', 'auditor', 'employee')
def suppliers():
    suppliers = Supplier.query.all()
    return render_template('suppliers.html', suppliers=suppliers)


@app.route('/create_contrato', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_contrato():
    authors = Author.query.all()
    origins = Origin.query.all()
    procedimentos = Procedimento.query.all()
    classifications = Classification.query.all()
    sectors = Sector.query.all()
    directorates = Directorate.query.all()
    instruments = Instrument.query.all()
    last_updates = LastUpdate.query.all()
    users = User.query.all()
    suppliers = Supplier.query.all()

    if request.method == 'POST':
        initial_balance = float(request.form['initial_balance'])
        new_contrato = Contrato(
            title=request.form['title'],
            start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d'),
            end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d'),
            initial_balance=initial_balance,
            balance=initial_balance,
            contrato_number=request.form['contrato_number'],
            original_process=int(request.form['original_process']),
            update_date=datetime.strptime(request.form['update_date'], '%Y-%m-%d'),
            update_protocol=int(request.form['update_protocol']),
            duration=int(request.form['duration']),
            monthly_value=float(request.form['monthly_value']),
            total_value=float(request.form['total_value']),
            author_id=int(request.form['author_id']),
            origin_id=int(request.form['origin_id']),
            procedimento_id=int(request.form['procedimento_id']),
            classification_id=int(request.form['classification_id']),
            sector_id=int(request.form['sector_id']),
            directorate_id=int(request.form['directorate_id']),
            instrument_id=int(request.form['instrument_id']),
            last_update_id=int(request.form['last_update_id']),
            supplier_id=int(request.form['supplier_id'])
        )


        # Retrieve manager and auditor objects by their IDs
        manager_ids = [int(manager_id) for manager_id in request.form.getlist('manager_id[]')]
        auditor_ids = [int(auditor_id) for auditor_id in request.form.getlist('auditor_id[]')]

        managers = User.query.filter(User.id.in_(manager_ids)).all()
        auditors = User.query.filter(User.id.in_(auditor_ids)).all()

        # Add managers and auditors to the many-to-many relationship
        new_contrato.managers = managers
        new_contrato.auditors = auditors

        db.session.add(new_contrato)
        db.session.commit()

        flash('Contrato criado com sucesso!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('create_contrato.html', authors=authors, origins=origins,
                           procedimentos=procedimentos, classifications=classifications, sectors=sectors,
                           directorates=directorates, instruments=instruments, last_updates=last_updates,
                           users=users, suppliers=suppliers)




@app.route('/contratos/<int:contrato_id>')
@login_required
def contrato_details(contrato_id):
    contrato = Contrato.query.get_or_404(contrato_id)
    # Obter todos os ItemDocumentoFiscalizacao associados ao contrato
    itens_documento = ItemDocumentoFiscalizacao.query.filter_by(contrato_id=contrato.id).all()

    # Obter todas as observações mensais associadas a esses itens
    observacoes = []
    for item in itens_documento:
        observacoes.extend(item.observacoes_mensais)

    # Agora, obter combinações únicas de mês e ano dessas observações
    unique_mes_ano = set([(obs.mes, obs.ano) for obs in observacoes])

    return render_template('contrato_details.html', contrato=contrato, unique_mes_ano=unique_mes_ano)



@app.route('/edit_contrato/<int:contrato_id>', methods=['GET', 'POST'])
@login_required
@contrato_access_required
def edit_contrato(contrato_id):
    contrato = Contrato.query.get_or_404(contrato_id)
    authors = Author.query.all()
    origins = Origin.query.all()
    procedimentos = Procedimento.query.all()
    classifications = Classification.query.all()
    sectors = Sector.query.all()
    directorates = Directorate.query.all()
    instruments = Instrument.query.all()
    last_updates = LastUpdate.query.all()
    users = User.query.all()
    suppliers = Supplier.query.all()

    manager_ids = [manager.id for manager in contrato.managers]
    auditor_ids = [auditor.id for auditor in contrato.auditors]

    if request.method == 'POST':
        contrato.title = request.form['title']
        contrato.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        contrato.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        contrato.balance = float(request.form['balance'])
        contrato.contrato_number = request.form['contrato_number']
        contrato.original_process = int(request.form['original_process'])
        contrato.update_date = datetime.strptime(request.form['update_date'], '%Y-%m-%d')
        contrato.update_protocol = int(request.form['update_protocol'])
        contrato.duration = int(request.form['duration'])        
        contrato.monthly_value = float(request.form['monthly_value'])
        contrato.total_value = float(request.form['total_value'])

        manager_ids = [manager.id for manager in contrato.managers]
        auditor_ids = [auditor.id for auditor in contrato.auditors]
        # Relational data
        contrato.author_id = int(request.form['author_id'])
        contrato.origin_id = int(request.form['origin_id'])
        contrato.procedimento_id = int(request.form['procedimento_id'])
        contrato.classification_id = int(request.form['classification_id'])
        contrato.sector_id = int(request.form['sector_id'])
        contrato.directorate_id = int(request.form['directorate_id'])
        contrato.instrument_id = int(request.form['instrument_id'])
        contrato.last_update_id = int(request.form['last_update_id'])
        contrato.supplier_id = int(request.form['supplier_id'])




        new_manager_ids = [int(manager_id) for manager_id in request.form.getlist('manager_id[]')]
        new_auditor_ids = [int(auditor_id) for auditor_id in request.form.getlist('auditor_id[]')]

        new_managers = User.query.filter(User.id.in_(new_manager_ids)).all()
        new_auditors = User.query.filter(User.id.in_(new_auditor_ids)).all()

        # Update managers and auditors in the many-to-many relationship
        contrato.managers = new_managers
        contrato.auditors = new_auditors


        db.session.commit()

        flash('Contrato atualizado com sucesso!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('edit_contrato.html', contrato=contrato, authors=authors, origins=origins,
                           procedimentos=procedimentos, classifications=classifications, sectors=sectors,
                           directorates=directorates, instruments=instruments, last_updates=last_updates,
                           users=users, suppliers=suppliers, manager_ids=manager_ids, auditor_ids=auditor_ids)




@app.route('/contratos/<int:contrato_id>/delete', methods=['POST'])
@login_required
def delete_contrato(contrato_id):
    contrato = Contrato.query.get_or_404(contrato_id)
    db.session.delete(contrato)
    db.session.commit()
    flash('Contrato deleted successfully!', 'success')
    return redirect(url_for('contratos'))


@app.route('/contratos/<int:contrato_id>/audit', methods=['GET', 'POST'])
@login_required
def contrato_audit(contrato_id):
    contrato = Contrato.query.get_or_404(contrato_id)
    
    if request.method == 'POST':
        month = int(request.form['month'])
        year = int(request.form['year'])
        notes = request.form['notes']
        audit_type = request.form['audit_type']  # Added retrieval of audit_type from the form
        
        attachment = request.files.get('attachment')
        if attachment:
            filename = documents.save(attachment)
        else:
            filename = None
        
        # Added audit_type to ContratoAudit record creation
        audit = ContratoAudit(contrato_id=contrato.id, month=month, year=year, audit_type=audit_type, notes=notes, attachment=filename)
        db.session.add(audit)
        db.session.commit()
        
        flash('Audit added successfully!', 'success')
        return redirect(url_for('contrato_audit', contrato_id=contrato.id))

    audits = (ContratoAudit.query
    .filter_by(contrato_id=contrato.id)
    .order_by(ContratoAudit.audit_type, ContratoAudit.year, ContratoAudit.month)
    .all())

    return render_template('contrato_audit.html', contrato=contrato, audits=audits)



@app.route('/observacoes/<int:contrato_id>/', methods=['GET', 'POST'])
def observacoes_mensais(contrato_id):
    # Fetch all items for the given contract
    itens = ItemDocumentoFiscalizacao.query.filter_by(contrato_id=contrato_id).all()
    itens_gerais = ItemObservacoesGerais.query.filter_by(contrato_id=contrato_id).all()
    
    if request.method == 'POST':
        mes = request.form.get('mes')
        ano = request.form.get('ano')
        observacoes_gerais = request.form.get('observacoes_gerais')
        

        
        for item in itens:
            observacao = request.form.get(f'observacao_{item.id}')
            status = request.form.get(f'status_{item.id}')
            
            # Create new ItemObservacaoMensal and save to DB
            nova_observacao = ItemObservacaoMensal(
                item_documento_id=item.id,
                observacao=observacao,
                status=status,
                mes=mes,
                ano=ano
            )
            db.session.add(nova_observacao)
        
        nova_observacao_geral = ItemObservacoesGerais(
        contrato_id=contrato_id,
        mes=mes,
        ano=ano,
        observacoes_gerais=observacoes_gerais
    )
        db.session.add(nova_observacao_geral)

        db.session.commit()
        # Redirect or show a success message

    return render_template('observacoes_template.html', itens=itens, itens_gerais=itens_gerais, contrato_id=contrato_id)


@app.route('/edit_observacoes/<int:contrato_id>/<int:mes>/<int:ano>/', methods=['GET', 'POST'])
def edit_observacoes_mensais(contrato_id, mes, ano):

    observacao_geral = ItemObservacoesGerais.query.filter_by(contrato_id=contrato_id, mes=mes, ano=ano).first()

    # Obter as observações mensais para o contrato, mês e ano especificados
    observacoes = db.session.query(ItemObservacaoMensal).join(ItemDocumentoFiscalizacao).filter(
        ItemDocumentoFiscalizacao.contrato_id == contrato_id,
        ItemObservacaoMensal.mes == mes,
        ItemObservacaoMensal.ano == ano
    ).all()

    if request.method == 'POST':
        # Atualize as observações conforme necessário
        # Você pode iterar sobre as observações e atualizar cada uma delas
        # com base nos dados enviados no POST
        for obs in observacoes:
            # Exemplo: atualizar a observação e o status
            obs.observacao = request.form.get(f'observacao_{obs.id}')
            obs.status = request.form.get(f'status_{obs.id}')
        


        # Atualiza as observações gerais
        observacoes_gerais = request.form.get('observacoes_gerais')
        if observacao_geral:
            observacao_geral.observacoes_gerais = observacoes_gerais
        else:
            # Se não existir uma observação geral, crie uma nova
            nova_observacao_geral = ItemObservacoesGerais(
                contrato_id=contrato_id,
                mes=mes,
                ano=ano,
                observacoes_gerais=observacoes_gerais
            )
            db.session.add(nova_observacao_geral)

        db.session.commit()
        # Redirecione para onde você quiser depois de salvar as alterações, por exemplo, de volta para os detalhes do contrato
        return redirect(url_for('contrato_details', contrato_id=contrato_id))

    # Renderizar um template para editar as observações
    # Este template deve ter campos para editar cada observação e seu status
    return render_template('edit_observacoes.html', observacoes=observacoes, contrato_id=contrato_id, mes=mes, ano=ano,observacoes_gerais=observacao_geral.observacoes_gerais if observacao_geral else '')


@app.route('/delete-observacoes/<int:contrato_id>/<int:mes>/<int:ano>/', methods=['POST'])
def delete_observacoes_mensais(contrato_id, mes, ano):
    # Filtra as observações mensais para o contrato, mês e ano fornecidos
    observacoes = db.session.query(ItemObservacaoMensal).join(ItemDocumentoFiscalizacao).filter(
        ItemDocumentoFiscalizacao.contrato_id == contrato_id,
        ItemObservacaoMensal.mes == mes,
        ItemObservacaoMensal.ano == ano
    ).all()

    # Deleta todas as observações filtradas
    for obs in observacoes:
        db.session.delete(obs)
    
    db.session.commit()

    # Redireciona o usuário para a página de detalhes do contrato após a exclusão
    return redirect(url_for('contrato_details', contrato_id=contrato_id))




@app.route('/fiscalizacao/<int:contrato_id>/<int:mes>/<int:ano>/')
def fiscalizacao(contrato_id, mes, ano):
    # Buscando os dados do contrato
    contrato = Contrato.query.get_or_404(contrato_id)
    
    # Buscando as observações para o contrato, mês e ano fornecidos
    observacoes = db.session.query(ItemObservacaoMensal).join(
        ItemDocumentoFiscalizacao, 
        ItemObservacaoMensal.item_documento_id == ItemDocumentoFiscalizacao.id
    ).join(
        Contrato, 
        ItemDocumentoFiscalizacao.contrato_id == Contrato.id
    ).filter(
        Contrato.id == contrato_id,
        ItemObservacaoMensal.mes == mes,
        ItemObservacaoMensal.ano == ano
    ).all()


    observacoes_gerais = ItemObservacoesGerais.query.filter_by(
        contrato_id=contrato_id, 
        mes=mes, 
        ano=ano
    ).first()

    # Renderizando o template HTML
    image_logo = os.path.join(os.getcwd(), 'flaskContractManager/static', 'header.png')
    html = render_template('dynamic_fisque.html', 
                           contrato=contrato, 
                           mes=mes, 
                           ano=ano, 
                           observacoes=observacoes, 
                           observacoes_gerais=observacoes_gerais.observacoes_gerais if observacoes_gerais else '', 
                           image_logo=image_logo)
    
    # Convertendo o HTML em PDF com xhtml2pdf
    response = make_response()
    pdf = BytesIO()
    image_logo = "os.path.join(os.getcwd(), 'static', 'header.png')"

    pisa_status = pisa.CreatePDF(html, dest=pdf, image_logo=image_logo)
    pdf.seek(0)

    # Verificar se ocorreu um erro na conversão
    if pisa_status.err:
        return 'We had some errors <pre>' + html + '</pre>'

    # Definindo os headers da resposta HTTP
    response.data = pdf.read()
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=out.pdf'
    response.status_code = 200

    return response




@app.route('/documents/<int:audit_id>/download')
@login_required
def download_document(audit_id):
    audit = ContratoAudit.query.get_or_404(audit_id)
    document_path = os.path.join(app.config['UPLOADED_DOCUMENTS_DEST'], audit.attachment)
    return send_file(document_path, as_attachment=True, download_name=audit.attachment)


@app.route('/contratos/<int:contrato_id>/create_table', methods=['GET', 'POST'])
@login_required
def create_contrato_table(contrato_id):
    contrato = Contrato.query.get_or_404(contrato_id)

    if request.method == 'POST':
        table_name = request.form['table_name']
        column_data = request.form.getlist('column_name[]')
        column_types = request.form.getlist('column_type[]')

        columns = {}
        for name, col_type in zip(column_data, column_types):
            if col_type == 'String':
                columns[name] = String
            elif col_type == 'Integer':
                columns[name] = Integer


        dynamic_table = create_dynamic_table(table_name, columns, contrato_id, db.metadata)
        flash('Tabela criada com sucesso!', 'success')
        return redirect(url_for('contrato_details', contrato_id=contrato_id))

    return render_template('create_contrato_table.html', contrato=contrato)


def create_dynamic_table(table_name, columns, contrato_id, metadata):
    new_columns = [Column('id', Integer, primary_key=True), Column('contrato_id', Integer, ForeignKey('contratos.id'))]

    for column_name, column_type in columns.items():
        new_columns.append(Column(column_name, column_type))

    table = Table(table_name, metadata, *new_columns)
    metadata.create_all()

    return table


@app.route('/debit', methods=['GET', 'POST'])
def debit_contrato():
    if request.method == 'GET':
        return render_template('debit_form.html')
    try:
        # Extrair os dados do corpo da requisição
        contrato_number = request.form.get('contrato_number')
        debit_value = request.form.get('debit_value')
        debit_month = request.form.get('debit_month')
        debit_year = request.form.get('debit_year')

        # Converter debit_value para float
        debit_value = float(debit_value)

        # Verificar se todos os campos foram fornecidos
        if not all([contrato_number, debit_value, debit_month, debit_year]):
            return jsonify({'error': 'Por favor, forneça o número do contrato, o valor do débito, o mês e o ano do débito.'}), 400

        # Buscar o contrato pelo número
        contrato = Contrato.query.filter_by(contrato_number=contrato_number).first()

        # Verificar se o contrato foi encontrado
        if not contrato:
            return jsonify({'error': f'Contrato com o número {contrato_number} não encontrado.'}), 404

        # Realizar o débito
        contrato.debit(debit_value, debit_month, debit_year)

        # Retornar uma resposta de sucesso
        return jsonify({'success': f'Débito de {debit_value} realizado com sucesso no contrato {contrato_number}.'}), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())  # Adicione esta linha
        return jsonify({'error': 'Ocorreu um erro ao processar a requisição. Por favor, tente novamente.'}), 500









@app.route('/create_supplier', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'employee')
def create_supplier():
    if request.method == 'POST':
        name = request.form['name']
        contact_info = request.form['contact_info']
        cnpj = request.form['cnpj']
        address = request.form['address']

        new_supplier = Supplier(name=name, contact_info=contact_info, cnpj=cnpj, address=address)
        db.session.add(new_supplier)
        db.session.commit()

        flash('Supplier created successfully')
        return redirect(url_for('suppliers'))

    return render_template('create_supplier.html')


@app.route('/delete_supplier/<int:supplier_id>', methods=['POST'])
@login_required
@role_required('admin', 'employee')
def delete_supplier(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)
    db.session.delete(supplier)
    db.session.commit()

    flash('Supplier deleted successfully')
    return redirect(url_for('suppliers'))


@app.route('/edit_supplier/<int:supplier_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'employee')
def edit_supplier(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)

    if request.method == 'POST':
        supplier.name = request.form['name']
        supplier.contact_info = request.form['contact_info']
        supplier.cnpj = request.form['cnpj']
        supplier.address = request.form['address']

        db.session.commit()

        flash('Supplier updated successfully')
        return redirect(url_for('suppliers'))

    return render_template('edit_supplier.html', supplier=supplier)


@app.route('/users')
@login_required
@role_required('admin')
def users():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        contact_info = request.form['contact_info']
        position = request.form['position']
        department = request.form['department']
        role_id = request.form['role_id']
        email = request.form['email']

        user.username = username

        if password:  # Update password only if a new one is provided
            hashed_password = generate_password_hash('admin')

            user.password = hashed_password

        user.name = name
        user.contact_info = contact_info
        user.position = position
        user.department = department
        user.role_id = role_id
        user.email = email

        db.session.commit()

        flash('Usuário atualizado com sucesso!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('edit_user.html', user=user, roles=roles)



@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')  # Only allow users with the 'admin' role to delete users
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.")
        return redirect(url_for('users'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('users'))


@app.route('/document_templates/create', methods=['GET', 'POST'])
@login_required
def create_document_template():
    if request.method == 'POST':
        name = request.form['name']

        file = request.files['template_file']
        if file.filename.endswith('.doc'):
            file_path = documents.save(file)
            document_template = DocumentTemplate(name=name, file_path=file_path)
            db.session.add(document_template)
            db.session.commit()
            flash('Modelo de documento criado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Arquivo inválido. Apenas arquivos .doc são permitidos.', 'danger')

    return render_template('create_document_template.html')


@app.route('/document_templates', methods=['GET'])
@login_required
def list_document_templates():
    document_templates = DocumentTemplate.query.all()
    return render_template('list_document_templates.html', document_templates=document_templates)


@app.route('/document_templates/<int:document_template_id>/download')
@login_required
def download_document_template(document_template_id):
    document_template = DocumentTemplate.query.get_or_404(document_template_id)
    document_path = os.path.join(app.config['UPLOADED_DOCUMENTS_DEST'], document_template.file_path)
    return send_file(document_path, as_attachment=True, download_name=document_template.file_path.split('/')[-1])


@app.route('/authors/create', methods=['GET', 'POST'])
@login_required
def create_author():
    if request.method == 'POST':
        name = request.form['name']
        new_author = Author(name=name)
        db.session.add(new_author)
        db.session.commit()
        flash('Autor criado com sucesso!', 'success')
        return redirect(url_for('dashboard'))  # Substitua 'dashboard' pelo nome da função da rota para a qual você deseja redirecionar

    return render_template('create_author.html')  # Substitua 'create_author.html' pelo nome do template do formulário de criação de autores

@app.route('/authors/edit/<int:author_id>', methods=['GET', 'POST'])
@login_required
def edit_author(author_id):
    author = Author.query.get_or_404(author_id)
    
    if request.method == 'POST':
        new_name = request.form['name']
        author.name = new_name
        db.session.commit()
        flash('Author updated successfully!', 'success')
        return redirect(url_for('authors_list'))  # Substitua 'authors_list' pela rota correta para listar os autores

    return render_template('edit_author.html', author=author)  # Substitua 'edit_author.html' pelo nome do seu template


@app.route('/authors/delete/<int:author_id>', methods=['POST'])
@login_required
def delete_author(author_id):
    author = Author.query.get_or_404(author_id)
    db.session.delete(author)
    db.session.commit()
    flash('Author deleted successfully!', 'success')
    return redirect(url_for('authors_list'))  # Substitua 'authors_list' pela rota correta para listar os autores


@app.route('/origins/create', methods=['GET', 'POST'])
@login_required
def create_origin():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            new_origin = Origin(name=name)
            db.session.add(new_origin)
            db.session.commit()
            flash('Origin created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('create_origin.html')

@app.route('/origins/edit/<int:origin_id>', methods=['GET', 'POST'])
@login_required
def edit_origin(origin_id):
    origin = Origin.query.get_or_404(origin_id)

    if request.method == 'POST':
        name = request.form['name']
        if name:
            origin.name = name
            db.session.commit()
            flash('Origin updated successfully!', 'success')
            return redirect(url_for('origins_list'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('edit_origin.html', origin=origin)


@app.route('/origins/delete/<int:origin_id>', methods=['POST'])
@login_required
def delete_origin(origin_id):
    origin = Origin.query.get_or_404(origin_id)
    db.session.delete(origin)
    db.session.commit()
    flash('Origin deleted successfully!', 'success')
    return redirect(url_for('origins_list'))





# Procedimento routes

@app.route('/procedimentos/create', methods=['GET', 'POST'])
@login_required
def create_procedimento():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            procedimento = Procedimento(name=name)
            db.session.add(procedimento)
            db.session.commit()
            flash('Procedimento created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('create_procedimento.html')


@app.route('/procedimentos/edit/<int:procedimento_id>', methods=['GET', 'POST'])
@login_required
def edit_procedimento(procedimento_id):
    procedimento = Procedimento.query.get_or_404(procedimento_id)

    if request.method == 'POST':
        name = request.form['name']
        if name:
            procedimento.name = name
            db.session.commit()
            flash('Procedimento updated successfully!', 'success')
            return redirect(url_for('procedimentos_list'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('edit_procedimento.html', procedimento=procedimento)


@app.route('/procedimentos/delete/<int:procedimento_id>', methods=['POST'])
@login_required
def delete_procedimento(procedimento_id):
    procedimento = Procedimento.query.get_or_404(procedimento_id)
    db.session.delete(procedimento)
    db.session.commit()
    flash('Procedimento deleted successfully!', 'success')
    return redirect(url_for('procedimentos_list'))


# Classification routes
@app.route('/classifications/create', methods=['GET', 'POST'])
@login_required
def create_classification():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            classification = Classification(name=name)
            db.session.add(classification)
            db.session.commit()
            flash('Classification created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('create_classification.html')

@app.route('/classifications/edit/<int:classification_id>', methods=['GET', 'POST'])
@login_required
def edit_classification(classification_id):
    classification = Classification.query.get_or_404(classification_id)

    if request.method == 'POST':
        name = request.form['name']
        if name:
            classification.name = name
            db.session.commit()
            flash('Classification updated successfully!', 'success')
            return redirect(url_for('classifications_list'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('edit_classification.html', classification=classification)

@app.route('/classifications/delete/<int:classification_id>', methods=['POST'])
@login_required
def delete_classification(classification_id):
    classification = Classification.query.get_or_404(classification_id)
    db.session.delete(classification)
    db.session.commit()
    flash('Classification deleted successfully!', 'success')
    return redirect(url_for('classifications_list'))


# Sector routes

@app.route('/sectors/create', methods=['GET', 'POST'])
@login_required
def create_sector():
    directorates = Directorate.query.all()
    if request.method == 'POST':
        name = request.form['name']
        directorate_id = request.form['directorate']
        if name:
            new_sector = Sector(name=name, directorate_id=directorate_id)
            db.session.add(new_sector)
            db.session.commit()
            flash('Sector created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('create_sector.html', directorates=directorates)


@app.route('/sectors/edit/<int:sector_id>', methods=['GET', 'POST'])
@login_required
def edit_sector(sector_id):
    sector = Sector.query.get_or_404(sector_id)
    
    if request.method == 'POST':
        name = request.form['name']
        if name:
            sector.name = name
            db.session.commit()
            flash('Sector updated successfully!', 'success')
            return redirect(url_for('sectors_list'))
        else:
            flash('Name cannot be empty.', 'danger')
    
    return render_template('edit_sector.html', sector=sector)


@app.route('/sectors/delete/<int:sector_id>', methods=['POST'])
@login_required
def delete_sector(sector_id):
    sector = Sector.query.get_or_404(sector_id)
    db.session.delete(sector)
    db.session.commit()
    flash('Sector deleted successfully!', 'success')
    return redirect(url_for('sectors_list'))


@app.route('/get_sectors')
def get_sectors():
    directorate_id = request.args.get('directorate_id', type=int)
    if directorate_id:
        sectors = Sector.query.filter_by(directorate_id=directorate_id).all()
        return jsonify([{'id': sector.id, 'name': sector.name} for sector in sectors])
    else:
        return jsonify([])



# Directorate routes
@app.route('/directorates/create', methods=['GET', 'POST'])
@login_required
def create_directorate():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            new_directorate = Directorate(name=name)
            db.session.add(new_directorate)
            db.session.commit()
            flash('Directorate created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Name cannot be empty.', 'danger')

    return render_template('create_directorate.html')

@app.route('/directorates/edit/<int:directorate_id>', methods=['GET', 'POST'])
@login_required
def edit_directorate(directorate_id):
    directorate = Directorate.query.get_or_404(directorate_id)
    if request.method == 'POST':
        directorate.name = request.form['name']
        db.session.commit()
        flash('Diretoria atualizada com sucesso!', 'success')
        return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_directorates'

    return render_template('edit_directorate.html', directorate=directorate)



@app.route('/directorates/delete/<int:directorate_id>', methods=['POST'])
@login_required
def delete_directorate(directorate_id):
    directorate = Directorate.query.get_or_404(directorate_id)
    db.session.delete(directorate)
    db.session.commit()
    flash('Diretoria excluída com sucesso!', 'success')
    return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_directorates'



# Instrument routes
@app.route('/instruments/create', methods=['GET', 'POST'])
@login_required
def create_instrument():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            new_instrument = Instrument(name=name)
            db.session.add(new_instrument)
            db.session.commit()
            flash('Instrumento criado com sucesso!', 'success')
            return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_instruments'
        else:
            flash('O nome do instrumento não pode estar vazio.', 'danger')
    
    return render_template('create_instrument.html')


@app.route('/instruments/edit/<int:instrument_id>', methods=['GET', 'POST'])
@login_required
def edit_instrument(instrument_id):
    instrument = Instrument.query.get_or_404(instrument_id)
    
    if request.method == 'POST':
        name = request.form['name']
        if name:
            instrument.name = name
            db.session.commit()
            flash('Instrumento atualizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_instruments'
        else:
            flash('O nome do instrumento não pode estar vazio.', 'danger')

    return render_template('edit_instrument.html', instrument=instrument)


@app.route('/instruments/delete/<int:instrument_id>', methods=['POST'])
@login_required
def delete_instrument(instrument_id):
    instrument = Instrument.query.get_or_404(instrument_id)
    db.session.delete(instrument)
    db.session.commit()
    flash('Instrumento excluído com sucesso!', 'success')
    return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_instruments'


# LastUpdate routes
@app.route('/last_updates/create', methods=['GET', 'POST'])
@login_required
def create_last_update():
    if request.method == 'POST':
        name = request.form['name']
        if not name:
            flash('O campo Nome é obrigatório.', 'danger')
            return render_template('create_last_update.html')

        last_update = LastUpdate(name=name)
        db.session.add(last_update)
        db.session.commit()
        flash('Última atualização criada com sucesso!', 'success')
        return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_last_updates'

    return render_template('create_last_update.html')


@app.route('/last_updates/edit/<int:last_update_id>', methods=['GET', 'POST'])
@login_required
def edit_last_update(last_update_id):
    last_update = LastUpdate.query.get_or_404(last_update_id)

    if request.method == 'POST':
        name = request.form['name']
        if not name:
            flash('O campo Nome é obrigatório.', 'danger')
            return render_template('edit_last_update.html', last_update=last_update)

        last_update.name = name
        db.session.commit()
        flash('Última atualização atualizada com sucesso!', 'success')
        return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_last_updates'

    return render_template('edit_last_update.html', last_update=last_update)


@app.route('/last_updates/delete/<int:last_update_id>', methods=['POST'])
@login_required
def delete_last_update(last_update_id):
    last_update = LastUpdate.query.get_or_404(last_update_id)
    db.session.delete(last_update)
    db.session.commit()
    flash('Última atualização excluída com sucesso!', 'success')
    return redirect(url_for('dashboard'))  # Atualize isso para a URL correta, por exemplo, 'list_last_updates'


@app.route('/create_role', methods=['GET', 'POST'])
@login_required
def create_role():
    if not current_user.role.name == 'admin':
        return redirect(url_for('unauthorized'))

    if request.method == 'POST':
        role_name = request.form.get('name')
        if role_name:
            role = Role(name=role_name)
            db.session.add(role)
            db.session.commit()
            flash('Role criada com sucesso!', 'success')
            return redirect(url_for('create_role'))

    return render_template('create_role.html', title='Criar Role')


def add_financial_commitment_to_contrato(contrato_id, expense_code, title, value):
    contrato = Contrato.query.get(contrato_id)
    if not contrato:
        raise ValueError("Contrato não encontrado.")

    budget_allocation = BudgetAllocation.query.filter_by(expense_code=expense_code).first()
    if not budget_allocation:
        raise ValueError("Dotação orçamentária não encontrada.")

    if budget_allocation.value - value < 0:
        raise ValueError("Saldo insuficiente na dotação orçamentária.")

    budget_allocation.value -= value

    financial_commitment = FinancialCommitment(expense_code=expense_code, title=title, value=value, contrato_id=contrato_id)
    db.session.add(financial_commitment)
    db.session.commit()

@app.route('/add_financial_commitment', methods=['GET', 'POST'])
def add_financial_commitment():
    form = FinancialCommitmentForm()

    if form.validate_on_submit():
        contrato_id = form.contrato_id.data
        expense_code = form.expense_code.data
        title = form.title.data
        value = form.value.data

        try:
            add_financial_commitment_to_contrato(contrato_id, expense_code, title, value)
            flash('Empenho financeiro adicionado com sucesso!', 'success')
            return redirect(url_for('add_financial_commitment'))
        except ValueError as e:
            flash(str(e), 'danger')

    return render_template('add_financial_commitment.html', form=form)


@app.route('/list_financial_commitments')
def list_financial_commitments():
    financial_commitments = FinancialCommitment.query.all()
    return render_template('list_financial_commitments.html', financial_commitments=financial_commitments)


@app.route('/add_budget_allocation', methods=['GET', 'POST'])
def add_budget_allocation():
    form = BudgetAllocationForm()

    if form.validate_on_submit():
        expense_code = form.expense_code.data
        value = form.value.data

        try:
            insert_budget_allocation(expense_code, value)
            flash('Dotação orçamentária adicionada com sucesso!', 'success')
            return redirect(url_for('add_budget_allocation'))
        except Exception as e:
            flash(str(e), 'danger')

    return render_template('add_budget_allocation.html', form=form)



@app.route('/list_budget_allocations')
def list_budget_allocations():
    budget_allocations = BudgetAllocation.query.all()
    return render_template('list_budget_allocations.html', budget_allocations=budget_allocations)


def get_contratos_with_less_than_90_days_remaining():
    
    today = date.today()

    with db.session.no_autoflush:
        contratos = Contrato.query.all()

        contratos_to_notify = []

        for contrato in contratos:
            remaining_days = (contrato.end_date - today).days
            if remaining_days < 90:
                contrato.remaining_days = remaining_days
                contratos_to_notify.append(contrato)

    return contratos_to_notify




@app.route('/send_test_email')
def send_test_email():
    msg = Message("Test Email",
                  sender=("Your Name", "marcosbernardes@sesa.pr.gov.br"),
                  recipients=["marcos.bernardes.jr@gmail.com"])
    msg.body = "This is a test email sent from Flask-Mail."
    mail.send(msg)
    return "Email sent!"



@app.route('/send_email_expired')
def send_reminder_emails():
    contratos_to_notify = get_contratos_with_less_than_90_days_remaining()

    print("contratos_to_notify:", contratos_to_notify)  # Add this print statement

    for contrato in contratos_to_notify:
        print(f"Contrato {contrato.title} managers: {contrato.managers}")
        print(f"Contrato {contrato.title} auditors: {contrato.auditors}")
        gestor_emails = [manager.email for manager in contrato.managers]
        fiscal_emails = [auditor.email for auditor in contrato.auditors]
        contrato_id = contrato.title
        remaining_days = contrato.remaining_days

        print("gestor_emails:", gestor_emails)  # Add this print statement
        print("fiscal_emails:", fiscal_emails)  # Add this print statement

        msg = Message(
            'Lembrete de vencimento de contrato',
            sender='marcosbernardes@sesa.pr.gov.br',
            recipients=[email for sublist in [gestor_emails, fiscal_emails] for email in sublist],
        )
        msg.body = f"O contrato {contrato_id} vencerá em {remaining_days} dias."

        mail.send(msg)
    return "Email enviado!"



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_first_user()

    app.run(host='0.0.0.0',debug=True)



