document.getElementById('button').addEventListener('click', function() {
    console.log("Pulsante cliccato"); // Per verificare se il clic funziona

    fetch('/chiusura-chrome', { method: 'POST' })  // Chiamata alla rotta corretta
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Chrome chiuso con successo!');
            } else {
                alert('Errore nella chiusura di Chrome.');
            }
        })
        .catch(error => {
            console.error('Errore:', error);
        });
});
