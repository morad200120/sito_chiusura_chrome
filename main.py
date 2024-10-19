from flask import Flask, render_template, request, redirect, url_for, flash, session
import user_agents

app = Flask(__name__)
app.secret_key = "s2f2h4*%!)81l#-nirpxe#*fd9-!+=&)0$ix=!8do%zot**z-p"

# Credenziali fisse (per semplicità)
USERNAME = "admin"
PASSWORD = "password123"

@app.route("/")
def ottieni_ua():
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)

    if ua.is_pc:
        return redirect(url_for("login_desktop"))
    else:
        return redirect(url_for("login_mobile"))

# Rotta per la pagina di login desktop
@app.route("/login_desktop", methods=["GET", "POST"])
def login_desktop():
    if request.method == "POST":
        return login()

    return render_template("login_desktop.html")

# Rotta per la pagina di login mobile
@app.route("/login_mobile", methods=["GET", "POST"])
def login_mobile():
    if request.method == "POST":
        return login()

    return render_template("login_mobile.html")

# Rotta per gestire il login (sia desktop che mobile)
@app.route("/login", methods=["POST"])
def login():
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)

    username_inserito = request.form.get("username")
    password_inserita = request.form.get("password")

    if username_inserito == USERNAME and password_inserita == PASSWORD:
        session['logged_in'] = True  # Imposta la sessione per indicare che l'utente è autenticato
        if ua.is_pc:
            return redirect(url_for("desktop"))
        else:
            return redirect(url_for("mobile"))
    else:
        error = "Credenziali non valide. Riprova."
        if ua.is_pc:
            return render_template("login_desktop.html", error=error)
        else:
            return render_template("login_mobile.html", error=error)

# Rotta per la dashboard desktop dopo il login
@app.route("/desktop")
def desktop():
    if not session.get('logged_in'):
        return redirect(url_for("ottieni_ua"))  # Reindirizza al login se non autenticato
    return render_template("desktop.html")

# Rotta per la dashboard mobile dopo il login
@app.route("/mobile")
def mobile():
    if not session.get('logged_in'):
        return redirect(url_for("ottieni_ua"))  # Reindirizza al login se non autenticato
    return render_template("mobile.html")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
