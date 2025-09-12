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
import stripe

# Configura Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


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
    def insert(self, *args, **kwargs): return self

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
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY')  # Coloque no .env

supabase: Client = None
supabase_admin: Client = None

if SUPABASE_AVAILABLE:
    # Cliente normal
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            app.logger.info("Cliente Supabase conectado com sucesso.")
        except Exception as e:
            app.logger.error(f"Erro ao conectar Supabase: {e}")
            supabase = MockSupabaseClient()
    else:
        app.logger.warning("SUPABASE_URL ou SUPABASE_KEY não definidos. Usando MockSupabaseClient.")
        supabase = MockSupabaseClient()

    # Cliente admin (service_role)
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        try:
            supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
            app.logger.info("Cliente admin Supabase (service_role) conectado.")
        except Exception as e:
            supabase_admin = None
            app.logger.error(f"Erro ao criar supabase_admin: {e}")
    else:
        app.logger.warning(f"SUPABASE_SERVICE_ROLE_KEY não definido. Admin client indisponível.")
else:
    app.logger.warning("Supabase não disponível. Usando mocks.")
    supabase = MockSupabaseClient()
    supabase_admin = None

app.logger.info(f"SUPABASE_AVAILABLE={SUPABASE_AVAILABLE}, supabase_admin={supabase_admin}")

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

# --- DECORATOR PARA ACESSO AO PRODUTO ---
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

                profile_column = f"{product_name}_is_active"
                profile = supabase.table('profiles').select(profile_column).eq('id', user.id).single().execute()
                if not profile.data or not profile.data.get(profile_column, False):
                    return redirect('/services.html')

            except Exception as e:
                app.logger.error(f"Erro acesso produto '{product_name}': {e}")
                return redirect('/login.html')

            return f(user, *args, **kwargs)
        return decorated_function
    return decorator


# --- API para criar sessão de checkout ---
@app.route("/api/create_checkout", methods=["POST"])
def create_checkout():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "Não autenticado"}), 401

    try:
        user_response = supabase.auth.get_user(token)
        user = user_response.user
        if not user:
            return jsonify({"error": "Usuário inválido"}), 401

        # Criar sessão Stripe Checkout
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{
                "price_data": {
                    "currency": "brl",
                    "product_data": {"name": "Site Personalizado"},
                    "unit_amount": 0,
                },
                "quantity": 1,
            }],
            metadata={"supabase_user_id": user.id},
            success_url="http://localhost:5000/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="http://localhost:5000/cancel",
            # Omita payment_method_types ou defina como [] para no-cost
        )

        return jsonify({"url": session.url})

    except Exception as e:
        app.logger.error(f"Erro ao criar checkout: {e}")
        return jsonify({"error": "Falha ao criar checkout"}), 500


# --- Webhook Stripe ---
@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError as e:
        app.logger.error(f"Assinatura inválida no webhook: {e}")
        return "Assinatura inválida", 400

    app.logger.info(f"Evento recebido: {event}")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        app.logger.info(f"Checkout session: {session}")

        user_id = session.get("metadata", {}).get("supabase_user_id")
        app.logger.info(f"user_id extraído: {user_id}")

        if not user_id:
            app.logger.error("Webhook não recebeu supabase_user_id no metadata.")
            return "No user_id", 400

        if not supabase_admin:
            app.logger.error("supabase_admin não definido. Não é possível atualizar a tabela.")
            return "Admin client unavailable", 500

        try:
            # CHAMANDO A FUNÇÃO RPC CORRETA
            result = supabase_admin.rpc(
                "admin_set_sitepersonalizado_is_active",
                {"p_user_id": user_id, "p_is_active": True}
            ).execute()
            app.logger.info(f"Produto ativado para usuário {user_id}. Resultado: {result}")
        except Exception as e:
            app.logger.error(f"Erro ao atualizar Supabase via RPC: {e}")
            return "Erro interno", 500

# --- ROTAS PÚBLICAS ---
@app.route('/')
def redirect_to_home():
    return redirect('home')

@app.route('/home')
def index(): return render_template('index.html')

@app.route('/services.html')
def services(): return render_template('services.html')

@app.route('/privacy.html')
def privacy(): return render_template('privacy.html')

@app.route('/login.html')
def login_page():
    token = request.cookies.get('access_token')
    if token:
        try:
            user_response = supabase.auth.get_user(token)
            if user_response.user:
                return redirect('/home')
        except:
            pass
    return render_template('login.html')

@app.route("/success")
def success():
    return render_template("success.html")

@app.route("/cancel")
def cancel():
    return render_template("cancel.html")


# --- ROTAS PROTEGIDAS ---
@app.route('/sitepersonalizado')
@app.route('/sitepersonalizado.html')
def sitepersonalizado():
    return render_template('sitepersonalizado.html')

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
        resp.set_cookie(
            'access_token',
            session_data.session.access_token,
            httponly=True,
            secure=not app.debug,  # True em produção HTTPS
            samesite='Lax',
            max_age=30*24*60*60  # cookie válido por 30 dias
        )

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
        user_response = supabase.auth.sign_up({'email': email, 'password': password})
        if not user_response or not getattr(user_response, 'user', None):
            app.logger.error(f"Falha ao criar usuário no Supabase: {user_response}")
            return jsonify({'error': 'Falha ao criar usuário'}), 400

        user = user_response.user
        # Cria perfil padrão com produtos inativos
        profile_result = supabase.table('profiles').insert({
            'id': user.id,
            'sitepersonalizado_is_active': False
        }).execute()

        # Verifica se inserção deu certo
        if profile_result.get('status_code', 200) >= 400:
            app.logger.error(f"Falha ao criar perfil: {profile_result}")
            return jsonify({'error': 'Falha ao criar perfil'}), 500

        return jsonify({'message': 'Registro OK. Verifique seu email.'}), 201

    except Exception as e:
        app.logger.exception(f"Erro registro {email}: {e}")
        return jsonify({'error': 'Erro no registro'}), 500


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
        profile_resp = supabase.table('profiles').select(profile_column).eq('id', user.id).execute()
        profile_data = profile_resp.data

        if not profile_data or not profile_data[0].get(profile_column, False):
            return jsonify({profile_column: False})

        return jsonify({profile_column: profile_data[0][profile_column]})

    except Exception as e:
        app.logger.error(f"Erro check_product {product_name}: {e}")
        return jsonify({'error': 'Falha ao consultar produto'}), 500

# --- API ADMIN (ativação) ---
@app.route('/admin/activate_sitepersonalizado/<uuid:user_id>', methods=['POST'])
def admin_activate_sitepersonalizado(user_id):
    if not supabase_admin:
        return jsonify({'error': 'Admin client indisponível'}), 500
    api_key = request.headers.get('X-Admin-API-Key')
    if api_key != ADMIN_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        # CHAMANDO A FUNÇÃO RPC
        supabase_admin.rpc(
            "admin_set_sitepersonalizado_is_active",
            {"p_user_id": str(user_id), "p_is_active": True}
        ).execute()
        return jsonify({"message": "Produto ativado com sucesso"})
    except Exception as e:
        app.logger.error(f"Erro ativar produto via RPC: {e}")
        return jsonify({'error': 'Falha ativar produto'}), 500


# --- LOGOUT ---
@app.route('/logout')
def logout():
    resp = make_response(redirect('/home'))
    is_secure = not app.debug
    # cookie deve ser removido do path '/' para afetar todas rotas
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