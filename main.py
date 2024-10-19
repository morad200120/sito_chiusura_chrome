from flask import Flask, render_template, request, redirect, url_for, flash
import user_agents

app = Flask(__name__)
app.secret_key = "s2f2h4*%!)81l#-nirpxe#*fd9-!+=&)0$ix=!8do%zot**z-p"

# Credenziali fisse (per semplicità)
USERNAME = "admin"
PASSWORD = "password123"

@app.route("/")
def ottieni_ua():
    # Rileva l'User-Agent e determina se è PC o Mobile
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)

    if ua.is_pc:
        return redirect(url_for("mostra_login_desktop"))
    else:
        return redirect(url_for("mostra_login_mobile"))

# Rotta per la pagina di login desktop
@app.route("/login_desktop")
def mostra_login_desktop():
    return render_template("login_desktop.html")

# Rotta per la pagina di login mobile
@app.route("/login_mobile")
def mostra_login_mobile():
    return render_template("login_mobile.html")

# Rotta per la dashboard desktop dopo il login
@app.route("/desktop")
def desktop():
    return render_template("desktop.html")

# Rotta per la dashboard mobile dopo il login
@app.route("/mobile")
def mobile():
    return render_template("mobile.html")

# Rotta per gestire il login (sia desktop che mobile)
@app.route("/login", methods=["GET", "POST"])
def login():
    # Rileva User-Agent all'interno della richiesta per ogni accesso
    user_agent = request.headers.get('User-Agent')
    ua = user_agents.parse(user_agent)

    if request.method == "POST":
        # Ottieni username e password dal form
        username_inserito = request.form.get("username")
        password_inserita = request.form.get("password")

        # Verifica le credenziali
        if username_inserito == USERNAME and password_inserita == PASSWORD:
            # Se il login ha successo, reindirizza alla dashboard giusta (desktop o mobile)
            if ua.is_pc:
                return redirect(url_for("desktop"))
            else:
                return redirect(url_for("mobile"))
        else:
            # Se il login fallisce, mostra un errore
            error = "Credenziali non valide. Riprova."
            if ua.is_pc:
                return render_template("login_desktop.html", error=error)
            else:
                return render_template("login_mobile.html", error=error)

    # Se il metodo è GET, mostra semplicemente il form di login
    if ua.is_pc:
        return render_template("login_desktop.html")
    else:
        return render_template("login_mobile.html")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
