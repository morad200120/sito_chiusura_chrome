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


    log_filename = "flask.log"

    logging.basicConfig(level=logging.INFO, 
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_filename), logging.StreamHandler()])
    
    logger = logging.getLogger(__name__)


    # ----------------------------------------------------------------------------------------------------

    USERNAME = os.getenv('USERNAME')
    PASSWORD = os.getenv('PASSWORD')

     # ----------------------------------------------------------------------------------------------------

    limiter = Limiter(app)  # Create limiter with just the app
    limiter.key_func = get_remote_address

    # ----------------------------------------------------------------------------------------------------

    def ottieni_ua(pc_route, mobile_route):
        user_agent = request.headers.get('User-Agent')
        ua = user_agents.parse(user_agent)
        return redirect(url_for(pc_route if ua.is_pc else mobile_route))

    # ----------------------------------------------------------------------------------------------------

    @app.route("/", methods=["GET"])
    def first_redirect():
        return ottieni_ua("login_desktop", "login_mobile")
    
    # ----------------------------------------------------------------------------------------------------

    failed_attempts = {}
    BLOCK_TIME = timedelta(minutes=15)

    @app.route("/login", methods=["POST", "GET"])
    @limiter.limit("5 per minute")
    def login():
        username = request.form.get("username")
        password = request.form.get("password")
        ip_address = request.remote_addr

        current_time = datetime.now()

        if ip_address in failed_attempts:
            failed_data = failed_attempts[ip_address]
            if failed_data['attempts'] >= 3 and (current_time - failed_data['last_attempt']) < BLOCK_TIME:
                flash("Troppi tentativi falliti. Riprovare più tardi.", "error")
                return redirect(url_for("login"))
            elif (current_time - failed_data['last_attempt']) > BLOCK_TIME:
                failed_attempts[ip_address] = {'attempts': 0, 'last_attempt': current_time}


        if username == USERNAME and password == PASSWORD:
            failed_attempts[ip_address] = {'attempts': 0, 'last_attempt': current_time}  
            return ottieni_ua("desktop", "mobile")
        else:
            flash("Username o password errati", "error")
            failed_attempts[ip_address] = {'attempts': failed_attempts.get(ip_address, {}).get('attempts', 0) + 1, 'last_attempt': current_time}
            return redirect(url_for("login"))

    # ----------------------------------------------------------------------------------------------------
        
    @app.route("/spegnimento", methods=["POST"])
    @limiter.limit("1 per minute")
    def spegnimento():
        try:
            seconds = 90
            subprocess.run(f"shutdown /s /t {seconds}", shell=True, check=True)
            
            flash("Il computer si spegnerà a breve.", "success")
            return ottieni_ua("desktop", "mobile")
        except Exception as e:
            flash(f"Errore durante lo spegnimento: {str(e)}", "error")
            logger.error(f"Error during shutdown: {str(e)}")
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
        app.run(debug=True, host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
        
    run_server()

#----------------------------------------------------------------------------------------------------