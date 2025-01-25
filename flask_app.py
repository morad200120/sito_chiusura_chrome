from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from datetime import datetime, timedelta
import time
import user_agents
import subprocess

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
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))

# ----------------------------------------------------------------------------------------------------
# Configurazione dei logger
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Configurazione degli handler per diversi livelli di log
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Handler per i vari livelli di log
    handlers = {
        logging.DEBUG: logging.FileHandler("debug.log", encoding='utf-8'),
        logging.INFO: logging.FileHandler("info.log", encoding='utf-8'),
        logging.WARNING: logging.FileHandler("warning.log", encoding='utf-8'),
        logging.ERROR: logging.FileHandler("error.log", encoding='utf-8'),
        logging.CRITICAL: logging.FileHandler("critical.log", encoding='utf-8')
    }

    # Aggiunta dei filtri per ogni livello
    for level, handler in handlers.items():
        handler.setLevel(level)
        handler.setFormatter(log_format)
        logger.addHandler(handler)

    return logger

logger = setup_logger()

# ----------------------------------------------------------------------------------------------------
# Funzione per ottenere l'User-Agent e redirigere in base al tipo di dispositivo
def ottieni_ua(pc_template, mobile_template):
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)
    return render_template(pc_template if ua.is_pc else mobile_template)

# ----------------------------------------------------------------------------------------------------
# Definizione delle variabili di login
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')

# ----------------------------------------------------------------------------------------------------
# Funzione per loggare i dettagli della richiesta
def log_request_data():
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)
    device = ua.device.family
    browser = ua.browser.family
    model = ua.device.model if ua.device.model else "Unknown"
    ip_address = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Data e ora

    logger.info(f"Data/Ora: {timestamp} | IP: {ip_address} | Dispositivo: {device} | "
                f"Browser: {browser} | Modello: {model}")

# ----------------------------------------------------------------------------------------------------
# Route per la prima redirezione
@app.route("/", methods=["GET"])
def first_redirect():
    logger.info("Richiesta ricevuta: Prima redirezione")
    log_request_data()
    return redirect(url_for("login_dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per il login
@app.route("/login", methods=["POST", "GET"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip_address = request.remote_addr
    current_time = datetime.now()

    # Verifica delle credenziali
    if username == USERNAME and password == PASSWORD:
        log_request_data()
        logger.info(f"Login riuscito per {username} da {ip_address}")
        return redirect(url_for("dashboard"))
    else:
        flash("Username o password errati", "error")
        log_request_data()
        logger.error(f"Login fallito per {username} da {ip_address}")
        return redirect(url_for("login_dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per il comando di spegnimento del computer
@app.route("/spegnimento", methods=["POST"])
def spegnimento():
    try:
        seconds = 90
        subprocess.run(f"shutdown /s /t {seconds}", shell=True, check=True)
        logger.info(f"Il computer si spegnerà tra {seconds} secondi.")
        flash("Il computer si spegnerà a breve.", "success")
        return ottieni_ua("desktop", "mobile")
    except Exception as e:
        logger.error(f"Errore durante lo spegnimento: {str(e)}")
        flash(f"Errore durante lo spegnimento: {str(e)}", "error")
        return redirect(url_for("dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per la pagina di login desktop
@app.route("/login_dashboard", methods=["GET"])
def login_dashboard():
    return ottieni_ua("login_desktop", "login_mobile")

# ----------------------------------------------------------------------------------------------------

# Route per la pagina desktop
@app.route("/dashboard", methods=["GET"])
def dashboard():
    return ottieni_ua("desktop", "mobile")

# ----------------------------------------------------------------------------------------------------
# Funzione per avviare il server
def run_server(port):
    logger.info(f"Avviando il sito sulla porta {port}...")
    app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)

# ----------------------------------------------------------------------------------------------------
# Avvio del server sulla porta desiderata
if __name__ == "__main__":
    run_server(8080)
