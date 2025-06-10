import os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, time
import re

app = Flask(__name__)

# ✅ CONFIGURAÇÃO CORS SIMPLIFICADA - SEM DUPLICAÇÃO
CORS(app, 
     origins=["http://localhost:3000", "http://localhost:5173", "espaco88frontend-production.up.railway.app"],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization', 'X-User-Id', 'Origin', 'Accept', 'X-Requested-With'],
     supports_credentials=True,
     expose_headers=['Content-Type', 'Authorization']
)

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

# Configuração do banco de dados MELHORADA
if os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('DATABASE_URL'):
    # Configuração para Railway/Produção
    database_url = os.getenv('DATABASE_URL')
    # Fix para Railway: substituir postgres:// por postgresql://
    if database_url and database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"🐘 Usando PostgreSQL: {database_url[:50]}...")
else:
    # Configuração local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'
    print("📁 Usando SQLite local")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===================== MODELOS =====================

# Modelo do usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    type = db.Column(db.String(10), nullable=False)  
    avatar_url = db.Column(db.Text, nullable=True)  
    
    # Relacionamentos
    barber_appointments = db.relationship('Appointment', foreign_keys='Appointment.barber_id', backref='barber', lazy='dynamic')
    client_appointments = db.relationship('Appointment', foreign_keys='Appointment.client_id', backref='client', lazy='dynamic')
    services = db.relationship('Service', backref='barber', lazy='dynamic')
    schedules = db.relationship('BarberSchedule', backref='barber', lazy='dynamic')

# Modelo de serviços
class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # duração em minutos
    barber_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Modelo de horários disponíveis do barbeiro
class BarberSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    barber_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=False)  # 0=Segunda, 6=Domingo
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    active = db.Column(db.Boolean, default=True)

# Modelo de agendamentos
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    barber_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamento com serviço
    service = db.relationship('Service', backref='appointments')

# ===================== VALIDAÇÕES =====================

def validate_registration(data):
    errors = []
    name = data.get('name', '').strip()
    if not name:
        errors.append("Nome é obrigatório.")
    else:
        if len(name) < 3:
            errors.append("O nome deve ter no mínimo 3 caracteres.")
        if len(name) > 50:
            errors.append("O nome deve ter no máximo 50 caracteres.")
        if not re.match(r'^[A-Za-zÀ-ÿ\s]+$', name):
            errors.append("O nome deve conter apenas letras e espaços.")
    
    email = data.get('email', '').strip()
    if not email:
        errors.append("Email é obrigatório.")
    else:
        if len(email) > 100:
            errors.append("O email deve ter no máximo 100 caracteres.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("Email inválido.")
    
    password = data.get('password', '')
    if not password:
        errors.append("Senha é obrigatória.")
    else:
        if len(password) < 8:
            errors.append("A senha deve ter no mínimo 8 caracteres.")
        if len(password) > 20:
            errors.append("A senha deve ter no máximo 20 caracteres.")
        if not re.search(r'[A-Z]', password):
            errors.append("A senha deve conter pelo menos uma letra maiúscula.")
        if not re.search(r'\d', password):
            errors.append("A senha deve conter pelo menos um número.")
    
    confirm_password = data.get('confirmPassword', '')
    if not confirm_password:
        errors.append("Confirmação da senha é obrigatória.")
    elif password != confirm_password:
        errors.append("As senhas não coincidem.")
    
    phone = data.get('phone', '').strip()
    if not phone:
        errors.append("Telefone é obrigatório.")
    elif len(phone) > 15:
        errors.append("O telefone deve ter no máximo 15 caracteres.")
    
    user_type = data.get('type', '')
    if user_type not in ['barber', 'client']:
        errors.append("Tipo de usuário inválido.")
    
    return errors

# ===================== HEALTH CHECK MELHORADO =====================

@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    try:
        print("🏥 Health check solicitado")
        
        # Teste de conexão com banco
        db.create_all()
        
        # Teste básico de query
        users_count = User.query.count()
        
        health_data = {
            "status": "healthy", 
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "users_count": users_count,
            "version": "1.0.0",
            "environment": os.getenv('RAILWAY_ENVIRONMENT', 'development')
        }
        
        print(f"✅ Health check OK: {health_data}")
        return jsonify(health_data), 200
        
    except Exception as e:
        error_data = {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }
        print(f"❌ Health check failed: {error_data}")
        return jsonify(error_data), 500

# ===================== ENDPOINT HOME MELHORADO =====================

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    home_data = {
        "message": "🚀 API Espaço88 está funcionando!",
        "version": "1.0.0",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "health": "/health",
            "users": "/users",
            "login": "/auth/login",
            "barbers": "/barbers",
            "services": "/services",
            "appointments": "/appointments",
            "schedules": "/schedules"
        }
    }
    print(f"🏠 Endpoint raiz acessado: {home_data}")
    return jsonify(home_data)

# ===================== TRATAMENTO DE ERROS GLOBAL =====================

@app.errorhandler(500)
def internal_error(error):
    print(f"❌ Erro interno: {error}")
    db.session.rollback()
    return jsonify({
        'error': 'Erro interno do servidor',
        'timestamp': datetime.utcnow().isoformat()
    }), 500

@app.errorhandler(404)
def not_found(error):
    print(f"❌ Endpoint não encontrado: {request.url}")
    return jsonify({
        'error': 'Endpoint não encontrado',
        'timestamp': datetime.utcnow().isoformat(),
        'requested_url': request.url
    }), 404

@app.errorhandler(400)
def bad_request(error):
    print(f"❌ Requisição inválida: {error}")
    return jsonify({
        'error': 'Requisição inválida',
        'timestamp': datetime.utcnow().isoformat()
    }), 400

# ===================== ENDPOINTS DE USUÁRIO =====================

@app.route('/users', methods=['POST', 'OPTIONS'])
def register_user():
    try:
        print("📝 Tentativa de registro de usuário")
        data = request.get_json()
        if not data:
            return jsonify({"error": "Nenhum dado fornecido"}), 400
        
        print(f"📝 Dados recebidos: {data.get('email', 'N/A')}")
        
        errors = validate_registration(data)
        if errors:
            print(f"❌ Erros de validação: {errors}")
            return jsonify({"errors": errors}), 400
        
        if User.query.filter_by(email=data['email'].strip()).first():
            print(f"❌ Email já existe: {data['email']}")
            return jsonify({"error": "Email já cadastrado."}), 400
        
        hashed_password = generate_password_hash(data['password'])
        new_user = User(
            name=data['name'].strip(),
            email=data['email'].strip(),
            password=hashed_password,
            phone=data['phone'].strip(),
            type=data['type']
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        print(f"✅ Usuário criado: {new_user.email}")
        return jsonify({"message": "Usuário cadastrado com sucesso!"}), 201
        
    except Exception as e:
        print(f"❌ Erro no registro: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/auth/login', methods=['POST', 'OPTIONS'])
def login():
    try:
        print("🔐 Tentativa de login")
        data = request.get_json()
        
        if not data:
            print("❌ Nenhum dado fornecido")
            return jsonify({'error': 'Dados não fornecidos.'}), 400
            
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        print(f"🔐 Login para: {email}")
        
        if not email or not password:
            print("❌ Email ou senha vazios")
            return jsonify({'error': 'Email e senha são obrigatórios.'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            print(f"❌ Usuário não encontrado: {email}")
            return jsonify({'error': 'Email ou senha inválidos.'}), 401
            
        if not check_password_hash(user.password, password):
            print(f"❌ Senha incorreta para: {email}")
            return jsonify({'error': 'Email ou senha inválidos.'}), 401
        
        print(f"✅ Login bem-sucedido: {email}")
        
        return jsonify({
            'message': 'Login bem-sucedido',
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'type': user.type,
                'phone': user.phone
            },
            'token': 'FAKE-JWT-TOKEN'
        }), 200
        
    except Exception as e:
        print(f"❌ Erro no login: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
def update_user(user_id):
    try:
        print(f"👤 Buscando usuário: {user_id}")
        print(f"🔄 Atualizando usuário {user_id}")
        user = User.query.get_or_404(user_id)
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'type': user.type
        })
    except Exception as e:
        print(f"❌ Erro ao buscar usuário: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/users/me', methods=['GET', 'OPTIONS'])
def get_current_user():
    try:
        print("👤 Buscando usuário atual")
        
        # Por enquanto, vamos pegar o user_id do header Authorization
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            print("❌ Token não fornecido")
            return jsonify({'error': 'Token não fornecido'}), 401
        
        user_id = request.headers.get('X-User-Id')
        if not user_id:
            print("❌ User ID não fornecido")
            return jsonify({'error': 'User ID não fornecido'}), 401
        
        user = User.query.get_or_404(int(user_id))
        print(f"✅ Usuário atual encontrado: {user.email}")
        
        return jsonify({
            'message': f'Perfil atualizado com sucesso! Campos alterados: {fields_str}',
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'type': user.type,
                'avatar_url': user.avatar_url  
            },
            'updated_fields': updated_fields
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar usuário atual: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
def update_user(user_id):
    try:
        print(f"🔄 Atualizando usuário: {user_id}")
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'name' in data:
            user.name = data['name'].strip()
        if 'email' in data:
            # Verificar se email já existe para outro usuário
            existing_user = User.query.filter_by(email=data['email'].strip()).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'error': 'Email já está em uso'}), 400
            user.email = data['email'].strip()
        if 'phone' in data:
            user.phone = data['phone'].strip()
        if 'password' in data and data['password']:
            user.password = generate_password_hash(data['password'])
        
        db.session.commit()
        print(f"✅ Usuário atualizado: {user.email}")
        return jsonify({'message': 'Usuário atualizado com sucesso'})
    except Exception as e:
        print(f"❌ Erro na atualização: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== ENDPOINTS DE BARBEIROS =====================

@app.route('/barbers', methods=['GET', 'OPTIONS'])
def get_barbers():
    try:
        print("💇 Buscando barbeiros")
        barbers = User.query.filter_by(type='barber').all()
        print(f"✅ Encontrados {len(barbers)} barbeiros")
        return jsonify([{
            'id': barber.id,
            'name': barber.name,
            'email': barber.email,
            'phone': barber.phone
        } for barber in barbers])
    except Exception as e:
        print(f"❌ Erro ao buscar barbeiros: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== ENDPOINT MELHORADO PARA ATUALIZAÇÃO DE PERFIL =====================

@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        print(f"🔄 Atualizando usuário {user_id}")
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Nenhum dado fornecido'}), 400
        
        print(f"📝 Dados recebidos: {data}")
        
        # Validações de entrada
        updated_fields = []
        
        # Atualizar nome
        if 'name' in data and data['name']:
            new_name = data['name'].strip()
            if len(new_name) < 3:
                return jsonify({'error': 'O nome deve ter no mínimo 3 caracteres'}), 400
            if len(new_name) > 50:
                return jsonify({'error': 'O nome deve ter no máximo 50 caracteres'}), 400
            if not re.match(r'^[A-Za-zÀ-ÿ\s]+$', new_name):
                return jsonify({'error': 'O nome deve conter apenas letras e espaços'}), 400
            
            user.name = new_name
            updated_fields.append('nome')
            print(f"✅ Nome atualizado para: {new_name}")
        
        # Atualizar email
        if 'email' in data and data['email']:
            new_email = data['email'].strip().lower()
            if len(new_email) > 100:
                return jsonify({'error': 'O email deve ter no máximo 100 caracteres'}), 400
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                return jsonify({'error': 'Email inválido'}), 400
            
            # Verificar se email já existe para outro usuário
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'error': 'Este email já está sendo usado por outro usuário'}), 400
            
            user.email = new_email
            updated_fields.append('email')
            print(f"✅ Email atualizado para: {new_email}")
        
        # Atualizar telefone
        if 'phone' in data and data['phone']:
            new_phone = data['phone'].strip()
            if len(new_phone) > 15:
                return jsonify({'error': 'O telefone deve ter no máximo 15 caracteres'}), 400
            
            user.phone = new_phone
            updated_fields.append('telefone')
            print(f"✅ Telefone atualizado para: {new_phone}")
        
        # Atualizar senha
        if 'password' in data and data['password']:
            new_password = data['password']
            if len(new_password) < 8:
                return jsonify({'error': 'A senha deve ter no mínimo 8 caracteres'}), 400
            if len(new_password) > 20:
                return jsonify({'error': 'A senha deve ter no máximo 20 caracteres'}), 400
            if not re.search(r'[A-Z]', new_password):
                return jsonify({'error': 'A senha deve conter pelo menos uma letra maiúscula'}), 400
            if not re.search(r'\d', new_password):
                return jsonify({'error': 'A senha deve conter pelo menos um número'}), 400
            
            user.password = generate_password_hash(new_password)
            updated_fields.append('senha')
            print(f"✅ Senha atualizada")
        
        # Verificar se algo foi atualizado
        if not updated_fields:
            return jsonify({'error': 'Nenhum campo válido foi fornecido para atualização'}), 400
        
        # Salvar no banco de dados
        db.session.commit()
        
        # Log de sucesso
        fields_str = ', '.join(updated_fields)
        print(f"✅ Usuário {user_id} atualizado com sucesso. Campos: {fields_str}")
        
        # Retornar dados atualizados (sem senha)
        return jsonify({
            'message': f'Perfil atualizado com sucesso! Campos alterados: {fields_str}',
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'type': user.type
            },
            'updated_fields': updated_fields
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao atualizar usuário {user_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno do servidor: {str(e)}'}), 500

# ===================== ENDPOINT MELHORADO PARA BUSCAR PERFIL ATUAL =====================

@app.route('/users/me', methods=['GET'])
def get_current_user():
    try:
        # Obter user_id do header
        auth_header = request.headers.get('Authorization', '')
        user_id = request.headers.get('X-User-Id')
        
        print(f"🔍 Buscando perfil do usuário ID: {user_id}")
        
        if not auth_header:
            return jsonify({'error': 'Token de autorização não fornecido'}), 401
        
        if not user_id:
            return jsonify({'error': 'ID do usuário não fornecido no header'}), 401
        
        try:
            user_id_int = int(user_id)
        except ValueError:
            return jsonify({'error': 'ID do usuário inválido'}), 400
        
        user = User.query.get(user_id_int)
        if not user:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        print(f"✅ Perfil encontrado: {user.name} ({user.email})")
        
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'type': user.type,
            'avatar_url': user.avatar_url
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar perfil: {str(e)}")
        return jsonify({'error': f'Erro interno do servidor: {str(e)}'}), 500

# ===================== ENDPOINT PARA VALIDAR EMAIL DISPONIBILIDADE =====================

@app.route('/users/check-email', methods=['POST'])
def check_email_availability():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        current_user_id = data.get('current_user_id')
        
        if not email:
            return jsonify({'error': 'Email é obrigatório'}), 400
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({'error': 'Email inválido'}), 400
        
        # Verificar se email já existe
        existing_user = User.query.filter_by(email=email).first()
        
        if existing_user and existing_user.id != current_user_id:
            return jsonify({
                'available': False,
                'message': 'Este email já está sendo usado por outro usuário'
            }), 200
        
        return jsonify({
            'available': True,
            'message': 'Email disponível'
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao verificar email: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500


# ===================== ENDPOINTS DE SERVIÇOS =====================

@app.route('/services', methods=['POST', 'OPTIONS'])
def create_service():
    try:
        print("✂️ Criando serviço")
        data = request.get_json()
        
        # Verificar se o usuário é barbeiro
        barber = User.query.get(data['barber_id'])
        if not barber or barber.type != 'barber':
            return jsonify({'error': 'Usuário não é um barbeiro'}), 400
        
        service = Service(
            name=data['name'],
            description=data.get('description', ''),
            price=data['price'],
            duration=data['duration'],
            barber_id=data['barber_id']
        )
        
        db.session.add(service)
        db.session.commit()
        
        print(f"✅ Serviço criado: {service.name}")
        return jsonify({
            'message': 'Serviço criado com sucesso',
            'service_id': service.id
        }), 201
    except Exception as e:
        print(f"❌ Erro ao criar serviço: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/services/<int:barber_id>', methods=['GET', 'OPTIONS'])
def get_services_by_barber(barber_id):
    try:
        print(f"✂️ Buscando serviços do barbeiro: {barber_id}")
        services = Service.query.filter_by(barber_id=barber_id, active=True).all()
        print(f"✅ Encontrados {len(services)} serviços")
        return jsonify([{
            'id': service.id,
            'name': service.name,
            'description': service.description,
            'price': service.price,
            'duration': service.duration
        } for service in services])
    except Exception as e:
        print(f"❌ Erro ao buscar serviços: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/services', methods=['GET', 'OPTIONS'])
def get_all_services():
    try:
        print("✂️ Buscando todos os serviços")
        services = Service.query.filter_by(active=True).all()
        return jsonify([{
            'id': service.id,
            'name': service.name,
            'description': service.description,
            'price': service.price,
            'duration': service.duration,
            'barber_name': service.barber.name,
            'barber_id': service.barber_id
        } for service in services])
    except Exception as e:
        print(f"❌ Erro ao buscar serviços: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/services/<int:service_id>', methods=['PUT', 'OPTIONS'])
def update_service(service_id):
    try:
        print(f"🔄 Atualizando serviço: {service_id}")
        service = Service.query.get_or_404(service_id)
        data = request.get_json()
        
        if 'name' in data:
            service.name = data['name']
        if 'description' in data:
            service.description = data['description']
        if 'price' in data:
            service.price = data['price']
        if 'duration' in data:
            service.duration = data['duration']
        if 'active' in data:
            service.active = data['active']
        
        db.session.commit()
        print(f"✅ Serviço atualizado: {service.name}")
        return jsonify({'message': 'Serviço atualizado com sucesso'})
    except Exception as e:
        print(f"❌ Erro ao atualizar serviço: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/services/<int:service_id>', methods=['DELETE', 'OPTIONS'])
def delete_service(service_id):
    try:
        print(f"🗑️ Deletando serviço: {service_id}")
        service = Service.query.get_or_404(service_id)
        service.active = False
        db.session.commit()
        print(f"✅ Serviço removido: {service.name}")
        return jsonify({'message': 'Serviço removido com sucesso'})
    except Exception as e:
        print(f"❌ Erro ao deletar serviço: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== ENDPOINTS DE HORÁRIOS =====================

@app.route('/schedules', methods=['POST', 'OPTIONS'])
def create_schedule():
    try:
        print("⏰ Criando horário")
        data = request.get_json()
        
        schedule = BarberSchedule(
            barber_id=data['barber_id'],
            day_of_week=data['day_of_week'],
            start_time=datetime.strptime(data['start_time'], '%H:%M').time(),
            end_time=datetime.strptime(data['end_time'], '%H:%M').time()
        )
        
        db.session.add(schedule)
        db.session.commit()
        
        print(f"✅ Horário criado para barbeiro: {data['barber_id']}")
        return jsonify({'message': 'Horário criado com sucesso'}), 201
    except Exception as e:
        print(f"❌ Erro ao criar horário: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/schedules/<int:barber_id>', methods=['GET', 'OPTIONS'])
def get_barber_schedule(barber_id):
    try:
        print(f"⏰ Buscando horários do barbeiro: {barber_id}")
        schedules = BarberSchedule.query.filter_by(barber_id=barber_id).order_by(BarberSchedule.day_of_week).all()
        
        result = [{
            'id': schedule.id,
            'day_of_week': schedule.day_of_week,
            'start_time': schedule.start_time.strftime('%H:%M'),
            'end_time': schedule.end_time.strftime('%H:%M'),
            'active': schedule.active
        } for schedule in schedules]
        
        print(f"✅ Encontrados {len(result)} horários")
        return jsonify(result)
    except Exception as e:
        print(f"❌ Erro ao buscar horários: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/schedules/<int:barber_id>/default', methods=['POST', 'OPTIONS'])
def create_default_schedule(barber_id):
    try:
        print(f"⏰ Criando horários padrão para barbeiro: {barber_id}")
        
        # Verificar se o barbeiro existe
        barber = User.query.get(barber_id)
        if not barber or barber.type != 'barber':
            return jsonify({'error': 'Barbeiro não encontrado'}), 404
        
        # Verificar se já tem horários cadastrados
        existing = BarberSchedule.query.filter_by(barber_id=barber_id).first()
        if existing:
            return jsonify({'error': 'Barbeiro já possui horários cadastrados'}), 400
        
        # Criar horários padrão (Segunda a Sábado, 9h às 19h)
        for day in range(6):  # 0=Segunda a 5=Sábado
            schedule = BarberSchedule(
                barber_id=barber_id,
                day_of_week=day,
                start_time=time(9, 0),  # 9:00
                end_time=time(19, 0),   # 19:00
                active=True
            )
            db.session.add(schedule)
        
        db.session.commit()
        print(f"✅ Horários padrão criados para barbeiro: {barber_id}")
        return jsonify({'message': 'Horários padrão criados com sucesso'}), 201
        
    except Exception as e:
        print(f"❌ Erro ao criar horários padrão: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/schedules/<int:schedule_id>', methods=['PUT', 'OPTIONS'])
def update_schedule(schedule_id):
    try:
        print(f"🔄 Atualizando horário: {schedule_id}")
        schedule = BarberSchedule.query.get_or_404(schedule_id)
        data = request.get_json()
        
        if 'day_of_week' in data:
            schedule.day_of_week = data['day_of_week']
        if 'start_time' in data:
            schedule.start_time = datetime.strptime(data['start_time'], '%H:%M').time()
        if 'end_time' in data:
            schedule.end_time = datetime.strptime(data['end_time'], '%H:%M').time()
        if 'active' in data:
            schedule.active = bool(data['active'])
        
        db.session.commit()
        
        print(f"✅ Horário atualizado: {schedule_id}")
        return jsonify({
            'message': 'Horário atualizado com sucesso',
            'schedule': {
                'id': schedule.id,
                'active': schedule.active
            }
        })
    except Exception as e:
        print(f"❌ Erro ao atualizar horário: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/schedules/<int:schedule_id>', methods=['DELETE', 'OPTIONS'])
def delete_schedule(schedule_id):
    try:
        print(f"🗑️ Excluindo horário: {schedule_id}")
        schedule = BarberSchedule.query.get_or_404(schedule_id)
        
        # Verificar se há agendamentos futuros para este horário
        future_appointments = Appointment.query.join(Service).filter(
            Appointment.barber_id == schedule.barber_id,
            Appointment.status == 'scheduled',
            Appointment.appointment_date > datetime.now(),
        ).first()
        
        if future_appointments:
            return jsonify({
                'error': 'Não é possível excluir este horário pois há agendamentos futuros. Desative temporariamente.'
            }), 400
        
        # Exclusão definitiva
        db.session.delete(schedule)
        db.session.commit()
        
        print(f"✅ Horário excluído: {schedule_id}")
        return jsonify({'message': 'Horário excluído permanentemente'})
        
    except Exception as e:
        print(f"❌ Erro ao excluir horário: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== ENDPOINTS DE AGENDAMENTOS =====================

@app.route('/appointments', methods=['POST', 'OPTIONS'])
def create_appointment():
    try:
        print("📅 Criando agendamento")
        data = request.get_json()
        
        appointment_date = datetime.fromisoformat(data['appointment_date'].replace('Z', '+00:00'))
        service = Service.query.get(data['service_id'])
        
        if not service:
            return jsonify({'error': 'Serviço não encontrado'}), 404
        
        end_time = appointment_date + timedelta(minutes=service.duration)
        
        # Verificar conflitos de horário
        conflicts = Appointment.query.filter(
            Appointment.barber_id == data['barber_id'],
            Appointment.status == 'scheduled',
            Appointment.appointment_date < end_time,
            Appointment.end_time > appointment_date
        ).first()
        
        if conflicts:
            return jsonify({'error': 'Horário não disponível'}), 400
        
        appointment = Appointment(
            client_id=data['client_id'],
            barber_id=data['barber_id'],
            service_id=data['service_id'],
            appointment_date=appointment_date,
            end_time=end_time,
            notes=data.get('notes', '')
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        print(f"✅ Agendamento criado: {appointment.id}")
        return jsonify({
            'message': 'Agendamento criado com sucesso',
            'appointment_id': appointment.id
        }), 201
        
    except Exception as e:
        print(f"❌ Erro ao criar agendamento: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/appointments/<int:user_id>', methods=['GET', 'OPTIONS'])
def get_user_appointments(user_id):
    try:
        print(f"📅 Buscando agendamentos do usuário: {user_id}")
        user = User.query.get_or_404(user_id)
        
        if user.type == 'client':
            appointments = Appointment.query.filter_by(client_id=user_id).all()
        else:  # barber
            appointments = Appointment.query.filter_by(barber_id=user_id).all()
        
        print(f"✅ Encontrados {len(appointments)} agendamentos")
        return jsonify([{
            'id': appointment.id,
            'client_name': appointment.client.name,
            'barber_name': appointment.barber.name,
            'service_name': appointment.service.name,
            'service_price': appointment.service.price,
            'appointment_date': appointment.appointment_date.isoformat(),
            'end_time': appointment.end_time.isoformat(),
            'status': appointment.status,
            'notes': appointment.notes
        } for appointment in appointments])
    except Exception as e:
        print(f"❌ Erro ao buscar agendamentos: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/appointments/<int:appointment_id>/status', methods=['PUT', 'OPTIONS'])
def update_appointment_status(appointment_id):
    try:
        print(f"🔄 Atualizando status do agendamento: {appointment_id}")
        appointment = Appointment.query.get_or_404(appointment_id)
        data = request.get_json()
        
        if data['status'] not in ['scheduled', 'completed', 'cancelled']:
            return jsonify({'error': 'Status inválido'}), 400
        
        appointment.status = data['status']
        db.session.commit()
        
        print(f"✅ Status atualizado: {appointment.id} -> {data['status']}")
        return jsonify({'message': 'Status atualizado com sucesso'})
    except Exception as e:
        print(f"❌ Erro ao atualizar status: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/appointments/<int:appointment_id>', methods=['DELETE', 'OPTIONS'])
def cancel_appointment(appointment_id):
    try:
        print(f"❌ Cancelando agendamento: {appointment_id}")
        appointment = Appointment.query.get_or_404(appointment_id)
        appointment.status = 'cancelled'
        db.session.commit()
        
        print(f"✅ Agendamento cancelado: {appointment.id}")
        return jsonify({'message': 'Agendamento cancelado com sucesso'})
    except Exception as e:
        print(f"❌ Erro ao cancelar agendamento: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== ENDPOINTS DE HORÁRIOS DISPONÍVEIS =====================

@app.route('/available-times/<int:barber_id>/<date>', methods=['GET', 'OPTIONS'])
def get_available_times(barber_id, date):
    try:
        print(f"⏰ Buscando horários disponíveis: barbeiro {barber_id}, data {date}")
        target_date = datetime.strptime(date, '%Y-%m-%d').date()
        day_of_week = target_date.weekday()  # 0=Monday, 6=Sunday
        
        # Buscar horário de trabalho do barbeiro
        schedule = BarberSchedule.query.filter_by(
            barber_id=barber_id,
            day_of_week=day_of_week,
            active=True
        ).first()
        
        if not schedule:
            print(f"❌ Barbeiro não trabalha neste dia: {day_of_week}")
            return jsonify([])  # Barbeiro não trabalha neste dia
        
        # Buscar agendamentos existentes
        existing_appointments = Appointment.query.filter(
            Appointment.barber_id == barber_id,
            Appointment.status == 'scheduled',
            db.func.date(Appointment.appointment_date) == target_date
        ).all()
        
        # Gerar slots de 30 minutos
        available_times = []
        current_time = datetime.combine(target_date, schedule.start_time)
        end_time = datetime.combine(target_date, schedule.end_time)
        
        while current_time < end_time:
            slot_end = current_time + timedelta(minutes=30)
            
            # Verificar se não há conflito
            conflict = any(
                apt.appointment_date < slot_end and apt.end_time > current_time
                for apt in existing_appointments
            )
            
            if not conflict:
                available_times.append(current_time.strftime('%H:%M'))
            
            current_time += timedelta(minutes=30)
        
        print(f"✅ Encontrados {len(available_times)} horários disponíveis")
        return jsonify(available_times)
        
    except Exception as e:
        print(f"❌ Erro ao buscar horários disponíveis: {str(e)}")
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

# ===================== INICIALIZAÇÃO MELHORADA =====================

if __name__ == '__main__':
    with app.app_context():
        try:
            print("🚀 Iniciando aplicação...")
            db.create_all()
            print("✅ Tabelas do banco criadas com sucesso!")
            
            # Verificar se há usuários
            users_count = User.query.count()
            print(f"📊 Total de usuários no banco: {users_count}")
            
        except Exception as e:
            print(f"❌ Erro ao criar tabelas: {e}")
    
    # Configuração dinâmica para Railway
    port = int(os.environ.get('PORT', 5000))
    debug = not bool(os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('DATABASE_URL'))
    
    print(f"🚀 Iniciando servidor na porta {port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🌍 Environment: {os.getenv('RAILWAY_ENVIRONMENT', 'development')}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)