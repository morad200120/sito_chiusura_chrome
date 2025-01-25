import threading
import flask_app
import ngrok_server
import invia_email
import time

#----------------------------------------------------------------------------------------------------

port = 8080

#----------------------------------------------------------------------------------------------------

def run_flask():
    flask_app.run_server(port)
                                                                        
def run_ngrok(event):
    ngrok_server.run_server(port, event)

def get_ngrok_url():
    while True:
        try:
            with open("link.txt", "r") as file:
                url = file.read().strip() 
            if url:
                return url
        except FileNotFoundError:
            print("Il file 'link.txt' non è stato trovato. Riprovo...")
        
        time.sleep(1) 

def send_email(event):
    event.wait()

    url = get_ngrok_url()  

    oggetto = "Duccio ha acceso il computer :)"
    contenuto = f"Duccio ha acceso il computer puoi spegnerlo da questo link: {url}"
    
    invia_email.invia_email(url, oggetto, contenuto)

#----------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    print("Avvio del server Flask e del tunnel ngrok...")

    event = threading.Event()

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    ngrok_thread = threading.Thread(target=run_ngrok, args=(event,), daemon=True)
    email_thread = threading.Thread(target=send_email, args=(event,), daemon=True)

    flask_thread.start()
    ngrok_thread.start()
    email_thread.start()

    try:
        while True:
            if not flask_thread.is_alive():
                print("Il server Flask si è arrestato.")
                break
            if not ngrok_thread.is_alive():
                print("Il tunnel ngrok si è arrestato.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("Chiusura del programma principale...")

#----------------------------------------------------------------------------------------------------
