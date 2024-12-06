from flask import Flask, render_template, request, redirect, url_for, flash, session
import user_agents
import subprocess
import invia_email
import ngrok_server
import threading

#----------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "s2f2h4*%!)81l#-nirpxe#*fd9-!+=&)0$ix=!8do%zot**z-p"

#----------------------------------------------------------------------------------------------------

USERNAME = "admin"
PASSWORD = "admin"

#----------------------------------------------------------------------------------------------------

def ottieni_ua(pc_route, mobile_route):
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)
    return redirect(url_for(pc_route if ua.is_pc else mobile_route))

#----------------------------------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def first_redirect():
    return ottieni_ua("login_desktop", "login_mobile")

#----------------------------------------------------------------------------------------------------

@app.route("/login_desktop", methods=["GET"])
def login_desktop():
    return render_template("login_desktop.html")
    
@app.route("/login_mobile", methods=["GET"])
def login_mobile():
    return render_template("login_mobile.html")

#----------------------------------------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == USERNAME and password == PASSWORD:
        return ottieni_ua("desktop", "mobile")
    else:
        flash("Username o password errati", "error")
        return ottieni_ua("login_desktop", "login_mobile")

#----------------------------------------------------------------------------------------------------

@app.route("/desktop")
def desktop():
    return render_template("desktop.html")

@app.route("/mobile")
def mobile():
    return render_template("mobile.html")

#----------------------------------------------------------------------------------------------------

@app.route("/spegnimento", methods=["POST"])
def spegnimento():
    try:
        subprocess.run("shutdown /s /t 0", shell=True)
        flash("Il computer si sta spegnendo...", "success")
    except Exception as e:
        flash(f"Errore durante lo spegnimento: {str(e)}", "error")
    finally:
        return ottieni_ua("login_desktop", "login_mobile")

#----------------------------------------------------------------------------------------------------

def start_ngrok(port):
    # Inizia il server ngrok in un thread separato
    url = ngrok_server.start_server(port)
    
    # Scrivi l'URL nel file e svuotalo
    with open("link.txt", "w") as file:
        file.write(url)

#----------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    # Porta per ngrok e Flask
    port = 8080

    # Avvia il server ngrok in un thread separato
    ngrok_thread = threading.Thread(target=start_ngrok, args=(port,))
    ngrok_thread.daemon = True  # La thread terminerà quando il programma principale termina
    ngrok_thread.start()

    # Avvia il server Flask
    app.run(debug=True, host='0.0.0.0', port=port)

