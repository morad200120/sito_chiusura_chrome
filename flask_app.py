# Importazione delle librerie
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from user_agents import parse

# ----------------------------------------------------------------------------------------------------
# Classe per filtrare i log in base al livello di severità
class LevelFilter(logging.Filter):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        # Restituisce True se il livello del log corrisponde a quello desiderato
        return record.levelno == self.level

# Funzione per configurare il logger
def setup_logger():
    logger = logging.getLogger(__name__)  # Ottieni un logger
    logger.setLevel(logging.DEBUG)  # Imposta il livello di log a DEBUG

    # Formato per i log
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Definizione dei file di log per ogni livello
    handlers = {
        logging.DEBUG: logging.FileHandler("debug.log", encoding='utf-8'),
        logging.INFO: logging.FileHandler("info.log", encoding='utf-8'),
        logging.WARNING: logging.FileHandler("warning.log", encoding='utf-8'),
        logging.ERROR: logging.FileHandler("error.log", encoding='utf-8'),
        logging.CRITICAL: logging.FileHandler("critical.log", encoding='utf-8')
    }

    # Aggiungi filtri per ogni livello e associa il formato di log
    for level, handler in handlers.items():
        handler.setLevel(level)
        handler.setFormatter(log_format)
        handler.addFilter(LevelFilter(level))  # Filtro per livello
        logger.addHandler(handler)

    return logger

# Inizializza il logger
logger = setup_logger()

# ----------------------------------------------------------------------------------------------------
# Carica le variabili d'ambiente dal file .env
load_dotenv()

# ----------------------------------------------------------------------------------------------------
# Crea l'app Flask e imposta la chiave segreta per la sessione
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# ----------------------------------------------------------------------------------------------------
# Ottieni le credenziali di login dall'ambiente
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')

# ----------------------------------------------------------------------------------------------------
# Funzione per determinare quale template caricare in base al tipo di dispositivo (desktop o mobile)
def ottieni_ua(pc_template, mobile_template):
    user_agent = request.headers.get('User-Agent')  # Ottieni l'User-Agent
    ua = parse(user_agent)  # Analizza l'User-Agent
    # Restituisci il template corrispondente in base al tipo di dispositivo
    return render_template(pc_template if ua.is_pc else mobile_template)

# ----------------------------------------------------------------------------------------------------
# Route principale che redirige all'area di login
@app.route("/", methods=["GET"])
def first_redirect():
    return redirect(url_for("login_dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per la gestione del login
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")  # Ottieni il nome utente
    password = request.form.get("password")  # Ottieni la password

    # Ottieni l'User-Agent e analizzalo
    user_agent = request.headers.get('User-Agent')
    ua = parse(user_agent)

    # Raccogli informazioni sul dispositivo dell'utente
    device_info = {
        "ip_address": get_remote_address() or "Unknown",  # Indirizzo IP
        "browser": ua.browser.family or "Unknown",  # Nome del browser
        "browser_version": ua.browser.version_string or "Unknown",  # Versione del browser
        "device": ua.device.family or "Unknown",  # Tipo di dispositivo
        "model": ua.device.model or "Unknown",  # Modello del dispositivo
        "OS": ua.os.family or "Unknown"  # Sistema operativo
    }

    # Verifica le credenziali
    if username == USERNAME and password == PASSWORD:
        # Log di accesso riuscito
        logger.info(f"Accesso eseguito con successo da "
                    f"ip_address: {device_info['ip_address']} "
                    f"browser: {device_info['browser']} "
                    f"browser_version: {device_info['browser_version']} "
                    f"device: {device_info['device']} "
                    f"model: {device_info['model']} "
                    f"OS: {device_info['OS']}")
        return redirect(url_for("dashboard"))  # Redirigi al dashboard
    else:
        # Log di accesso fallito
        logger.warning(f"Accesso fallito da "
            f"ip_address: {device_info['ip_address']} "
            f"browser: {device_info['browser']} "
            f"browser_version: {device_info['browser_version']} "
            f"device: {device_info['device']} "
            f"model: {device_info['model']} "
            f"OS: {device_info['OS']}")
        flash("Username o password errati", "error")  # Mostra messaggio di errore
        return redirect(url_for("login_dashboard"))

# ----------------------------------------------------------------------------------------------------
# Route per il template di login
@app.route("/login_dashboard", methods=["GET"])
def login_dashboard():
    return ottieni_ua("login_desktop.html", "login_mobile.html")

# ----------------------------------------------------------------------------------------------------
# Route per il dashboard
@app.route("/dashboard", methods=["GET"])
def dashboard():
    return ottieni_ua("desktop.html", "mobile.html")

# ----------------------------------------------------------------------------------------------------
# Route per spegnere il computer
@app.route("/spegnimento", methods=["POST"])
def spegnimento():
    try:
        seconds = 90  # Spegni il computer dopo 90 secondi
        subprocess.run(f"shutdown /s /t {seconds}", shell=True, check=True)  # Comando per spegnere il PC
        flash("Il computer si spegnerà a breve.", "success")  # Messaggio di successo
        return ottieni_ua("desktop", "mobile")  # Ritorna alla pagina del dashboard
    except Exception as e:
        flash(f"Errore durante lo spegnimento: {str(e)}", "error")  # Messaggio di errore
        return redirect(url_for("dashboard"))

# ----------------------------------------------------------------------------------------------------
# Funzione per avviare il server Flask su una porta specificata
def run_server(port):
    app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)

# ----------------------------------------------------------------------------------------------------
# Se il modulo viene eseguito direttamente, avvia il server Flask sulla porta 8080
if __name__ == "__main__":
    run_server(8080)
