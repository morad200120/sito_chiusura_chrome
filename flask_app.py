from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
from user_agents import parse
import os
from datetime import datetime, timedelta
import subprocess
from functools import wraps

# ----------------------------------------------------------------------------------------------------
# Caricamento delle variabili d'ambiente
load_dotenv()

# ----------------------------------------------------------------------------------------------------
# Configurazione dell'app Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_PERMANENT=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# ----------------------------------------------------------------------------------------------------
# Configurazione del logger
def setup_logger(log_file="app.log"):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(log_file, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ----------------------------------------------------------------------------------------------------
# Funzione per loggare i dettagli della richiesta
def log_request_data():
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ua = parse(user_agent)
    logger.info(f"IP: {request.remote_addr} | Device: {ua.device.family} | Browser: {ua.browser.family}")

# ----------------------------------------------------------------------------------------------------
# Funzione per redirigere in base al tipo di dispositivo
def determine_route(pc_route, mobile_route):
    ua = parse(request.headers.get('User-Agent', ''))
    return redirect(url_for(pc_route if ua.is_pc else mobile_route))

# ----------------------------------------------------------------------------------------------------
# Decoratore per verificare l'autenticazione
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Access denied. Please log in.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------------------------------
# Variabili di login
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')

# ----------------------------------------------------------------------------------------------------
# Route principale
@app.route("/", methods=["GET"])
def index():
    logger.info("Accesso alla homepage")
    log_request_data()
    return determine_route("login", "login")

# ----------------------------------------------------------------------------------------------------
# Route per il login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            flash("Login successful!", "success")
            logger.info(f"Login riuscito per {username} da {request.remote_addr}")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
            logger.warning(f"Login fallito per {username} da {request.remote_addr}")
            return redirect(url_for("login"))

    return render_template("login_desktop.html")

# ----------------------------------------------------------------------------------------------------
# Route per la dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    is_pc = parse(request.headers.get('User-Agent', '')).is_pc
    template = "desktop.html" if is_pc else "mobile.html"
    logger.info("Accesso alla dashboard")
    return render_template(template)

# ----------------------------------------------------------------------------------------------------
# Route per il comando di spegnimento
@app.route("/shutdown", methods=["POST"])
@login_required
def shutdown():
    try:
        seconds = 90
        subprocess.run(f"shutdown /s /t {seconds}", shell=True, check=True)
        logger.info(f"Il computer si spegnerà tra {seconds} secondi.")
        flash("The computer will shut down shortly.", "success")
    except Exception as e:
        logger.error(f"Errore durante lo spegnimento: {str(e)}")
        flash(f"Error during shutdown: {str(e)}", "error")
    return redirect(url_for("dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per il logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    logger.info("Logout eseguito.")
    return redirect(url_for("login"))

# ----------------------------------------------------------------------------------------------------
# Funzione per avviare il server
def run_server(port):
    logger.info(f"Avviando il sito sulla porta {port}...")
    app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)

# ----------------------------------------------------------------------------------------------------
# Avvio del server
if __name__ == "__main__":
    run_server(8080)
