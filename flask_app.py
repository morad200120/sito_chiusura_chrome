from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess
import win32api
import win32con
import time
import user_agents

# ----------------------------------------------------------------------------------------------------

def start_site(port):
    app = Flask(__name__)
    app.secret_key = "s2f2h4*%!)81l#-nirpxe#*fd9-!+=&)0$ix=!8do%zot**z-p"

    # ----------------------------------------------------------------------------------------------------

    USERNAME = "admin"
    PASSWORD = "admin"

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
            title = "Spegnimento computer"
            message = "Il computer si spegnerà fra 90 secondi"

            # Visualizza la finestra di messaggio
            win32api.MessageBox(0, message, title, win32con.MB_OK)

            # Attendere 90 secondi prima di eseguire lo spegnimento
            time.sleep(90)

            # Esegui il comando per spegnere il computer
            subprocess.run("shutdown /s /t 0", shell=True)

            flash("Il computer si è spento", "success")

        except Exception as e:
            flash(f"Errore durante lo spegnimento: {str(e)}", "error")

        finally:
            return ottieni_ua("login_desktop", "login_mobile")

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