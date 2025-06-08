import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo do usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # "barber" ou "client"

# Função de validação
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
            'type': user.type
        },
        'token': 'FAKE-JWT-TOKEN'
    }), 200

@app.route('/')
def home():
    return jsonify({"message": "API está no ar"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
