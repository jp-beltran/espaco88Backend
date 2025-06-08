import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re

app = Flask(__name__)
CORS(app)

# Configuração do banco de dados
if os.getenv('RAILWAY_ENVIRONMENT'):
    # Configuração para Railway
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
else:
    # Configuração local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===================== MODELOS =====================

# Modelo do usuário (já existente)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # "barber" ou "client"
    
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

# ===================== ENDPOINTS DE USUÁRIO =====================

@app.route('/users', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Nenhum dado fornecido"}), 400
    errors = validate_registration(data)
    if errors:
        return jsonify({"errors": errors}), 400
    if User.query.filter_by(email=data['email'].strip()).first():
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
    return jsonify({"message": "Usuário cadastrado com sucesso!"}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email e senha são obrigatórios.'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Email ou senha inválidos.'}), 401
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

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'type': user.type
    })

@app.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
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
    return jsonify({'message': 'Usuário atualizado com sucesso'})

# ===================== ENDPOINTS DE BARBEIROS =====================

@app.route('/barbers', methods=['GET'])
def get_barbers():
    barbers = User.query.filter_by(type='barber').all()
    return jsonify([{
        'id': barber.id,
        'name': barber.name,
        'email': barber.email,
        'phone': barber.phone
    } for barber in barbers])

# ===================== ENDPOINTS DE SERVIÇOS =====================

@app.route('/services', methods=['POST'])
def create_service():
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
    
    return jsonify({
        'message': 'Serviço criado com sucesso',
        'service_id': service.id
    }), 201

@app.route('/services/<int:barber_id>', methods=['GET'])
def get_services_by_barber(barber_id):
    services = Service.query.filter_by(barber_id=barber_id, active=True).all()
    return jsonify([{
        'id': service.id,
        'name': service.name,
        'description': service.description,
        'price': service.price,
        'duration': service.duration
    } for service in services])

@app.route('/services', methods=['GET'])
def get_all_services():
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

@app.route('/services/<int:service_id>', methods=['PUT'])
def update_service(service_id):
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
    return jsonify({'message': 'Serviço atualizado com sucesso'})

@app.route('/services/<int:service_id>', methods=['DELETE'])
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    service.active = False
    db.session.commit()
    return jsonify({'message': 'Serviço removido com sucesso'})

# ===================== ENDPOINTS DE HORÁRIOS =====================

@app.route('/schedules', methods=['POST'])
def create_schedule():
    data = request.get_json()
    
    schedule = BarberSchedule(
        barber_id=data['barber_id'],
        day_of_week=data['day_of_week'],
        start_time=datetime.strptime(data['start_time'], '%H:%M').time(),
        end_time=datetime.strptime(data['end_time'], '%H:%M').time()
    )
    
    db.session.add(schedule)
    db.session.commit()
    
    return jsonify({'message': 'Horário criado com sucesso'}), 201

@app.route('/schedules/<int:barber_id>', methods=['GET'])
def get_barber_schedule(barber_id):
    schedules = BarberSchedule.query.filter_by(barber_id=barber_id, active=True).all()
    return jsonify([{
        'id': schedule.id,
        'day_of_week': schedule.day_of_week,
        'start_time': schedule.start_time.strftime('%H:%M'),
        'end_time': schedule.end_time.strftime('%H:%M')
    } for schedule in schedules])

# ===================== ENDPOINTS DE AGENDAMENTOS =====================

@app.route('/appointments', methods=['POST'])
def create_appointment():
    data = request.get_json()
    
    try:
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
        
        return jsonify({
            'message': 'Agendamento criado com sucesso',
            'appointment_id': appointment.id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/appointments/<int:user_id>', methods=['GET'])
def get_user_appointments(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.type == 'client':
        appointments = Appointment.query.filter_by(client_id=user_id).all()
    else:  # barber
        appointments = Appointment.query.filter_by(barber_id=user_id).all()
    
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

@app.route('/appointments/<int:appointment_id>/status', methods=['PUT'])
def update_appointment_status(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    data = request.get_json()
    
    if data['status'] not in ['scheduled', 'completed', 'cancelled']:
        return jsonify({'error': 'Status inválido'}), 400
    
    appointment.status = data['status']
    db.session.commit()
    
    return jsonify({'message': 'Status atualizado com sucesso'})

@app.route('/appointments/<int:appointment_id>', methods=['DELETE'])
def cancel_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    appointment.status = 'cancelled'
    db.session.commit()
    
    return jsonify({'message': 'Agendamento cancelado com sucesso'})

# ===================== ENDPOINTS DE HORÁRIOS DISPONÍVEIS =====================

@app.route('/available-times/<int:barber_id>/<date>', methods=['GET'])
def get_available_times(barber_id, date):
    try:
        target_date = datetime.strptime(date, '%Y-%m-%d').date()
        day_of_week = target_date.weekday()  # 0=Monday, 6=Sunday
        
        # Buscar horário de trabalho do barbeiro
        schedule = BarberSchedule.query.filter_by(
            barber_id=barber_id,
            day_of_week=day_of_week,
            active=True
        ).first()
        
        if not schedule:
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
        
        return jsonify(available_times)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ===================== ENDPOINT HOME =====================

@app.route('/')
def home():
    return jsonify({"message": "API de Agendamento da Barbearia está no ar"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)