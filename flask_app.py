from flask import Flask, render_template, request, redirect, url_for, flash
import os
import time
import user_agents
import subprocess

# ----------------------------------------------------------------------------------------------------

def start_site(port):
    app = Flask(__name__)
    app.secret_key = "s2f2h4*%!)81l#-nirpxe#*fd9-!+=&)0$ix=!8do%zot**z-p"

    # ----------------------------------------------------------------------------------------------------

    USERNAME = "bloccocomputer"
    PASSWORD = "Bloccacifrolo2009!"

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

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            return ottieni_ua("desktop", "mobile")
        else:
            flash("Username o password errati", "error")
            return ottieni_ua("login_desktop", "login_mobile")
        
    # ----------------------------------------------------------------------------------------------------
        
    @app.route("/spegnimento", methods=["POST"])
    def spegnimento():
        try:
            seconds = 90
            subprocess.run(f"shutdown /s /t {seconds}", shell=True, check=True)
            
            flash("Il computer si spegnerà a breve.", "success")
            return ottieni_ua("desktop", "mobile")
        except Exception as e:
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
        print(f"Avviando il sito sulla porta {port}...")
        app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)
        
    run_server()

#----------------------------------------------------------------------------------------------------