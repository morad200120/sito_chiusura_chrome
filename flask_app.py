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

load_dotenv()

def start_site(port):

    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY")

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_PERMANENT=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))

    # ----------------------------------------------------------------------------------------------------

    # Crea un logger
    logger = logging.getLogger(__name__)

    # Imposta il livello di logging a DEBUG per catturare tutti i messaggi
    logger.setLevel(logging.DEBUG)

    # Crea gestori per ogni livello di log

    # Handler per i messaggi DEBUG
    debug_handler = logging.FileHandler("debug.log")
    debug_handler.setLevel(logging.DEBUG)

    # Filtro per accettare solo i log di livello DEBUG
    class OnlyDebugFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.DEBUG

    debug_handler.addFilter(OnlyDebugFilter())

    # Handler per i messaggi INFO
    info_handler = logging.FileHandler("info.log")
    info_handler.setLevel(logging.INFO)

    # Filtro per accettare solo i log di livello INFO
    class OnlyInfoFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.INFO

    info_handler.addFilter(OnlyInfoFilter())

    # Handler per i messaggi WARNING
    warning_handler = logging.FileHandler("warning.log")
    warning_handler.setLevel(logging.WARNING)

    # Filtro per accettare solo i log di livello WARNING
    class OnlyWarningFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.WARNING

    warning_handler.addFilter(OnlyWarningFilter())

    # Handler per i messaggi ERROR
    error_handler = logging.FileHandler("error.log")
    error_handler.setLevel(logging.ERROR)

    # Filtro per accettare solo i log di livello ERROR
    class OnlyErrorFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.ERROR

    error_handler.addFilter(OnlyErrorFilter())

    # Handler per i messaggi CRITICAL
    critical_handler = logging.FileHandler("critical.log")
    critical_handler.setLevel(logging.CRITICAL)

    # Filtro per accettare solo i log di livello CRITICAL
    class OnlyCriticalFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.CRITICAL

    critical_handler.addFilter(OnlyCriticalFilter())

    # Imposta il formato per tutti i messaggi di log
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Aggiungi il formato a tutti i gestori
    debug_handler = logging.FileHandler("debug.log", encoding='utf-8')
    info_handler = logging.FileHandler("info.log", encoding='utf-8')
    warning_handler = logging.FileHandler("warning.log", encoding='utf-8')
    error_handler = logging.FileHandler("error.log", encoding='utf-8')
    critical_handler = logging.FileHandler("critical.log", encoding='utf-8')


    # Aggiungi i gestori al logger
    logger.addHandler(debug_handler)
    logger.addHandler(info_handler)
    logger.addHandler(warning_handler)
    logger.addHandler(error_handler)
    logger.addHandler(critical_handler)

    # Test: diversi livelli di log
    logger.debug("Questo è un messaggio DEBUG")
    logger.info("Questo è un messaggio INFO")
    logger.warning("Questo è un messaggio WARNING")
    logger.error("Questo è un messaggio ERROR")
    logger.critical("Questo è un messaggio CRITICAL")



    # ----------------------------------------------------------------------------------------------------

    USERNAME = os.getenv('USERNAME')
    PASSWORD = os.getenv('PASSWORD')

    # ----------------------------------------------------------------------------------------------------

    def ottieni_ua(pc_route, mobile_route):
        user_agent = request.headers.get('User-Agent')
        ua = user_agents.parse(user_agent)
        return redirect(url_for(pc_route if ua.is_pc else mobile_route))
    
    # ----------------------------------------------------------------------------------------------------

    load_dotenv()

    def start_site(port):

        app = Flask(__name__)
        app.secret_key = os.getenv("FLASK_SECRET_KEY")

        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_PERMANENT=False,
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))

    # ----------------------------------------------------------------------------------------------------

    # Crea un logger
    logger = logging.getLogger(__name__)

    # Imposta il livello di logging a DEBUG per catturare tutti i messaggi
    logger.setLevel(logging.DEBUG)

    # Crea gestori per ogni livello di log

    # Handler per i messaggi DEBUG
    debug_handler = logging.FileHandler("debug.log")
    debug_handler.setLevel(logging.DEBUG)

    # Filtro per accettare solo i log di livello DEBUG
    class OnlyDebugFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.DEBUG

    debug_handler.addFilter(OnlyDebugFilter())

    # Handler per i messaggi INFO
    info_handler = logging.FileHandler("info.log")
    info_handler.setLevel(logging.INFO)

    # Filtro per accettare solo i log di livello INFO
    class OnlyInfoFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.INFO

    info_handler.addFilter(OnlyInfoFilter())

    # Handler per i messaggi WARNING
    warning_handler = logging.FileHandler("warning.log")
    warning_handler.setLevel(logging.WARNING)

    # Filtro per accettare solo i log di livello WARNING
    class OnlyWarningFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.WARNING

    warning_handler.addFilter(OnlyWarningFilter())

    # Handler per i messaggi ERROR
    error_handler = logging.FileHandler("error.log")
    error_handler.setLevel(logging.ERROR)

    # Filtro per accettare solo i log di livello ERROR
    class OnlyErrorFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.ERROR

    error_handler.addFilter(OnlyErrorFilter())

    # Handler per i messaggi CRITICAL
    critical_handler = logging.FileHandler("critical.log")
    critical_handler.setLevel(logging.CRITICAL)

    # Filtro per accettare solo i log di livello CRITICAL
    class OnlyCriticalFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.CRITICAL

    critical_handler.addFilter(OnlyCriticalFilter())

    # Imposta il formato per tutti i messaggi di log
    log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Aggiungi il formato a tutti i gestori
    debug_handler.setFormatter(log_format)
    info_handler.setFormatter(log_format)
    warning_handler.setFormatter(log_format)
    error_handler.setFormatter(log_format)
    critical_handler.setFormatter(log_format)

    # Aggiungi i gestori al logger
    logger.addHandler(debug_handler)
    logger.addHandler(info_handler)
    logger.addHandler(warning_handler)
    logger.addHandler(error_handler)
    logger.addHandler(critical_handler)

    # Test: diversi livelli di log
    logger.debug("Questo è un messaggio DEBUG")
    logger.info("Questo è un messaggio INFO")
    logger.warning("Questo è un messaggio WARNING")
    logger.error("Questo è un messaggio ERROR")
    logger.critical("Questo è un messaggio CRITICAL")


    # ----------------------------------------------------------------------------------------------------

    USERNAME = os.getenv('USERNAME')
    PASSWORD = os.getenv('PASSWORD')

    # ----------------------------------------------------------------------------------------------------

    def ottieni_ua(pc_route, mobile_route):
        user_agent = request.headers.get('User-Agent')
        ua = user_agents.parse(user_agent)
        return redirect(url_for(pc_route if ua.is_pc else mobile_route))
    
    # ----------------------------------------------------------------------------------------------------
    
    @app.route("/", methods=["GET"])
    def first_redirect():
        logger.info("Richiesta ricevuta: Prima redirezione")
        log_request_data()
        return ottieni_ua("login_desktop", "login_mobile")

    # ----------------------------------------------------------------------------------------------------

    failed_attempts = {}
    BLOCK_TIME = timedelta(minutes=15)

    @app.route("/login", methods=["POST", "GET"])
    def login():
        username = request.form.get("username")
        password = request.form.get("password")

        ip_address = request.remote_addr

        current_time = datetime.now()




        if request.method == 'GET':
            return render_template("login_desktop.html")


        if username == USERNAME and password == PASSWORD:
            failed_attempts[ip_address] = {'attempts': 0, 'last_attempt': current_time}
            log_request_data()  
            logger.info(f"Login riuscito per {username} da {ip_address}")
            return ottieni_ua("desktop", "mobile")
        else:
            failed_attempts[ip_address] = {
                'attempts': failed_attempts.get(ip_address, {}).get('attempts', 0) + 1,
                'last_attempt': current_time
            }
            flash("Username o password errati", "error")
            log_request_data() 
            logger.error(f"Login fallito per {username} da {ip_address}")
            return redirect(url_for("login"))

    # ----------------------------------------------------------------------------------------------------

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
            return ottieni_ua("desktop", "mobile")

    # ----------------------------------------------------------------------------------------------------

    @app.route("/login_desktop", methods=["GET"])
    def login_desktop():
        return render_template("login_desktop.html")

    @app.route("/login_mobile", methods=["GET"])
    def login_mobile():
        return render_template("login_mobile.html")
    
    # ----------------------------------------------------------------------------------------------------

    @app.route("/desktop")
    def desktop():
        return render_template("desktop.html")

    @app.route("/mobile")
    def mobile():
        return render_template("mobile.html")
    
    # ----------------------------------------------------------------------------------------------------

    def run_server():
        logger.info(f"Avviando il sito sulla porta {port}...")
        app.run(debug=True, host='0.0.0.0', port=8080, use_reloader=False)

    run_server()

#----------------------------------------------------------------------------------------------------


    # ----------------------------------------------------------------------------------------------------
    
    @app.route("/", methods=["GET"])
    def first_redirect():
        logger.info("Richiesta ricevuta: Prima redirezione")
        log_request_data()
        return ottieni_ua("login_desktop", "login_mobile")

    # ----------------------------------------------------------------------------------------------------

    failed_attempts = {}
    BLOCK_TIME = timedelta(minutes=15)

    @app.route("/login", methods=["POST", "GET"])
    def login():
        username = request.form.get("username")
        password = request.form.get("password")

        ip_address = request.remote_addr

        current_time = datetime.now()




        if request.method == 'GET':
            return render_template("login_desktop.html")


        if username == USERNAME and password == PASSWORD:
            failed_attempts[ip_address] = {'attempts': 0, 'last_attempt': current_time}
            log_request_data()  
            logger.info(f"Login riuscito per {username} da {ip_address}")
            return ottieni_ua("desktop", "mobile")
        else:
            failed_attempts[ip_address] = {
                'attempts': failed_attempts.get(ip_address, {}).get('attempts', 0) + 1,
                'last_attempt': current_time
            }
            flash("Username o password errati", "error")
            log_request_data() 
            logger.error(f"Login fallito per {username} da {ip_address}")
            return redirect(url_for("login"))

    # ----------------------------------------------------------------------------------------------------

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
            return ottieni_ua("desktop", "mobile")

    # ----------------------------------------------------------------------------------------------------

    @app.route("/login_desktop", methods=["GET"])
    def login_desktop():
        return render_template("login_desktop.html")

    @app.route("/login_mobile", methods=["GET"])
    def login_mobile():
        return render_template("login_mobile.html")
    
    # ----------------------------------------------------------------------------------------------------

    @app.route("/desktop")
    def desktop():
        return render_template("desktop.html")

    @app.route("/mobile")
    def mobile():
        return render_template("mobile.html")
    
    # ----------------------------------------------------------------------------------------------------

    def run_server():
        logger.info(f"Avviando il sito sulla porta {port}...")
        app.run(debug=True, host='0.0.0.0', port=8080, use_reloader=False)

    run_server()

#----------------------------------------------------------------------------------------------------
