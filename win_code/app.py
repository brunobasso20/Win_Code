import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, make_response, jsonify
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from functools import wraps
from types import SimpleNamespace

# Supabase
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    Client = object

load_dotenv()

# --- MOCK CLIENT PARA DESENVOLVIMENTO LOCAL ---
class MockAuth:
    def get_user(self, token):
        user_data = {'id': 'mock-user-id-123', 'email': 'dev@local.com'}
        return SimpleNamespace(user=SimpleNamespace(**user_data))
    def sign_in_with_password(self, credentials):
        session_data = {'access_token': 'mock-access-token', 'refresh_token': 'mock-refresh-token'}
        return SimpleNamespace(session=SimpleNamespace(**session_data))
    def sign_up(self, credentials):
        user_data = {'id': 'mock-user-id-456', 'email': credentials.get('email')}
        return SimpleNamespace(user=SimpleNamespace(**user_data))
    def sign_out(self):
        return None

class MockQueryBuilder:
    def select(self, *args, **kwargs): return self
    def eq(self, *args, **kwargs): return self
    def single(self): return self
    def execute(self):
        mock_profile_data = {'sitepersonalizado_is_active': True}
        return SimpleNamespace(data=mock_profile_data)

class MockSupabaseClient:
    def __init__(self):
        self.auth = MockAuth()
    def table(self, table_name): return MockQueryBuilder()
    def rpc(self, fn, params): return SimpleNamespace(data={"ok": True})

# --- APP ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(32))

# Segurança HTTP
csp = {
    'default-src': ['\'self\'', '*.supabase.co', 'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
    'script-src': ['\'self\'', 'cdn.jsdelivr.net'],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'fonts.googleapis.com', 'cdnjs.cloudflare.com'],
    'img-src': ['\'self\'', 'data:', 'images.unsplash.com']
}
talisman = Talisman(app, content_security_policy=csp)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour", "10 per minute"])

# --- SUPABASE ---
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')

supabase: Client
supabase_admin: Client

if SUPABASE_URL and SUPABASE_KEY and SUPABASE_AVAILABLE:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    app.logger.warning("Usando MockSupabaseClient (anon).")
    supabase = MockSupabaseClient()

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY and SUPABASE_AVAILABLE:
    try:
        supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        app.logger.info("Cliente admin Supabase (service_role) conectado.")
    except Exception as e:
        app.logger.error(f"Erro ao conectar supabase_admin: {e}")
        supabase_admin = None
else:
    supabase_admin = None
    app.logger.warning("SERVICE_ROLE_KEY não definido. Funções admin indisponíveis.")

# --- LOGGING ---
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'args') and isinstance(record.args, dict):
            if 'password' in record.args: record.args['password'] = '***'
        return True

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.addFilter(SensitiveDataFilter())
app.logger.setLevel(logging.INFO)

# --- DECORATOR TEMPORÁRIO PARA TESTE ---
def product_access_required(product_name: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.cookies.get('access_token')
            if not token:
                return redirect('/login.html')
            try:
                user_response = supabase.auth.get_user(token)
                user = user_response.user
                if not user:
                    return redirect('/login.html')

                # === REMOVIDO BLOQUEIO PARA TESTE ===
                # profile_column = f"{product_name}_is_active"
                # profile = supabase.table('profiles').select(profile_column).eq('id', user.id).single().execute()
                # if not profile.data or not profile.data.get(profile_column, False):
                #     return redirect('/services.html')

            except Exception as e:
                app.logger.error(f"Erro acesso produto '{product_name}': {e}")
                return redirect('/login.html')

            # Agora o usuário sempre pode entrar
            return f(user, *args, **kwargs)
        return decorated_function
    return decorator


# --- ROTAS PÚBLICAS ---
@app.route('/')
@app.route('/index.html')
def index(): return render_template('index.html')

@app.route('/services.html')
def services(): return render_template('services.html')

@app.route('/privacy.html')
def privacy(): return render_template('privacy.html')

@app.route('/login.html')
def login_page(): return render_template('login.html')

# --- ROTAS PROTEGIDAS ---
@app.route('/sitepersonalizado')
@app.route('/sitepersonalizado.html')
@product_access_required('sitepersonalizado')
def sitepersonalizado(current_user):
    return render_template('sitepersonalizado.html', user=current_user)

# --- API AUTH ---
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    data = request.json
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email e senha obrigatórios'}), 400
    try:
        session_data = supabase.auth.sign_in_with_password({'email': email, 'password': password})
        resp = make_response(jsonify({'message': 'Login OK'}))
        is_secure = not app.debug
        resp.set_cookie('access_token', session_data.session.access_token, httponly=True, secure=is_secure, samesite='Lax')
        return resp
    except Exception as e:
        app.logger.warning(f"Falha login {email}: {e}")
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per hour")
def api_register():
    data = request.json
    email, password = data.get('email'), data.get('password')
    if not email or not password or len(password) < 8:
        return jsonify({'error': 'Email e senha (mínimo 8 chars) obrigatórios'}), 400
    try:
        supabase.auth.sign_up({'email': email, 'password': password})
        return jsonify({'message': 'Registro OK. Verifique seu email.'}), 201
    except Exception as e:
        app.logger.error(f"Erro registro {email}: {e}")
        return jsonify({'error': 'Erro no registro'}), 400

# --- API CHECK PRODUCT ---
@app.route('/api/check_product/<product_name>', methods=['GET'])
def check_product(product_name):
    token = request.cookies.get('access_token')
    if not token:
        return jsonify({'error': 'Não autenticado'}), 401
    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        profile_column = f"{product_name}_is_active"
        profile = supabase.table('profiles').select(profile_column).eq('id', user.id).single().execute()
        return jsonify({profile_column: profile.data.get(profile_column, False)})
    except Exception as e:
        app.logger.error(f"Erro check_product {product_name}: {e}")
        return jsonify({'error': 'Falha ao consultar produto'}), 500

# --- API ADMIN (ativação) ---
@app.route('/admin/activate_sitepersonalizado/<uuid:user_id>', methods=['POST'])
def admin_activate_sitepersonalizado(user_id):
    if not supabase_admin:
        return jsonify({'error': 'Admin client indisponível'}), 500
    try:
        supabase_admin.table("profiles").update({"sitepersonalizado_is_active": True}).eq("id", str(user_id)).execute()
        return jsonify({"message": "Produto ativado com sucesso"})
    except Exception as e:
        app.logger.error(f"Erro ativar produto: {e}")
        return jsonify({'error': 'Falha ativar produto'}), 500

# --- LOGOUT ---
@app.route('/logout')
def logout():
    try:
        supabase.auth.sign_out()
    except Exception as e:
        app.logger.error(f"Erro logout: {e}")
    resp = make_response(redirect('/index.html'))
    is_secure = not app.debug
    resp.delete_cookie('access_token', path='/', samesite='Lax', secure=is_secure)
    return resp

# --- ERROS ---
@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except:
        return "<h1>404 - Página não encontrada</h1><a href='/'>Voltar ao início</a>", 404

@app.errorhandler(500)
def internal_server_error(e):
    try:
        return render_template('500.html'), 500
    except:
        return "<h1>500 - Erro interno do servidor</h1><a href='/'>Voltar ao início</a>", 500

# --- RUN ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)

