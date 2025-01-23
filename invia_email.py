import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#----------------------------------------------------------------------------------------------------

def invia_email(url, oggetto, contenuto):
    sender_email = "gpc493140@gmail.com"
    receiver_email = "botcomputerduccio@gmail.com"
    password = "wxjs osfv wdsu qloa"  # Usa una password per app se hai 2FA


    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = oggetto


    body = f"{contenuto}"
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)

        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email inviata con successo!")

    except Exception as e:
        print(f"Errore nell'invio dell'email: {e}")

    finally:
        server.quit()

#----------------------------------------------------------------------------------------------------