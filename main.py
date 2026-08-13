from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
import os
import uuid
import base64
import sqlite3
from datetime import datetime, timedelta
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = FastAPI()

# --- CONFIGURAZIONE INIZIALE ---
UPLOAD_DIR = "uploads"
DB_NAME = "trasferimenti.db"
DIMENSIONE_MASSIMA_MB = 200  # limite di sicurezza per non riempire il disco del servizio gratuito
PBKDF2_ITERAZIONI = 390_000

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (id TEXT PRIMARY KEY, nome_originale TEXT, data_scadenza TEXT, salt_b64 TEXT)''')
    # Compatibilità con database creati prima dell'introduzione della password:
    # se la colonna salt_b64 non esiste ancora, la aggiungiamo senza perdere i dati.
    try:
        c.execute("ALTER TABLE files ADD COLUMN salt_b64 TEXT")
    except sqlite3.OperationalError:
        pass  # la colonna esiste già
    conn.commit()
    conn.close()


init_db()


def pulizia_file_scaduti():
    """Elimina i file fisici e i record dal database quando scadono"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ora_attuale = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id FROM files WHERE data_scadenza < ?", (ora_attuale,))
    scaduti = c.fetchall()

    for row in scaduti:
        file_id = row[0]
        percorso_fisico = os.path.join(UPLOAD_DIR, file_id)
        if os.path.exists(percorso_fisico):
            try:
                os.remove(percorso_fisico)
            except Exception:
                pass
        c.execute("DELETE FROM files WHERE id = ?", (file_id,))

    conn.commit()
    conn.close()


def password_e_robusta(pw: str) -> bool:
    """Stessa regola applicata anche lato client: mai fidarsi solo del controllo nel browser."""
    if len(pw) < 10:
        return False
    ha_maiuscola = any(c.isupper() for c in pw)
    ha_minuscola = any(c.islower() for c in pw)
    ha_numero = any(c.isdigit() for c in pw)
    ha_simbolo = any(not c.isalnum() for c in pw)
    return ha_maiuscola and ha_minuscola and ha_numero and ha_simbolo


def deriva_chiave(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERAZIONI,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# --- INTERFACCIA UTENTE (pagina di invio) ---
@app.get("/", response_class=HTMLResponse)
async def home():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>File index.html non trovato! Assicurati che sia nella stessa cartella.</h1>"


# --- LOGICA DI CARICAMENTO (UPLOAD): il file viene cifrato PRIMA di essere scritto su disco ---
@app.post("/upload")
async def carica_file(request: Request, file: UploadFile = File(...), password: str = Form(...)):
    pulizia_file_scaduti()

    if not password_e_robusta(password):
        raise HTTPException(
            status_code=400,
            detail="Password troppo debole: servono almeno 10 caratteri con maiuscole, minuscole, numeri e simboli.",
        )

    dimensione_massima_byte = DIMENSIONE_MASSIMA_MB * 1024 * 1024
    contenuto = await file.read(dimensione_massima_byte + 1)
    if len(contenuto) > dimensione_massima_byte:
        raise HTTPException(status_code=413, detail=f"File troppo grande. Limite massimo: {DIMENSIONE_MASSIMA_MB} MB.")

    file_id = str(uuid.uuid4())
    salt = os.urandom(16)
    chiave = deriva_chiave(password, salt)
    contenuto_cifrato = Fernet(chiave).encrypt(contenuto)

    # Il file su disco si chiama SOLO come l'id generato dal server (mai come il
    # nome scelto da chi carica), per evitare che un nome tipo "../../x" possa
    # far scrivere il file fuori dalla cartella uploads.
    percorso = os.path.join(UPLOAD_DIR, file_id)
    with open(percorso, "wb") as buffer:
        buffer.write(contenuto_cifrato)

    scadenza = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO files (id, nome_originale, data_scadenza, salt_b64) VALUES (?, ?, ?, ?)",
        (file_id, file.filename, scadenza, base64.b64encode(salt).decode("ascii")),
    )
    conn.commit()
    conn.close()

    # Il link viene costruito dinamicamente in base a come è stata raggiunta questa
    # richiesta: niente indirizzo fisso nel codice (funziona sia in locale che su Render).
    base_url = str(request.base_url).rstrip("/")

    return {
        "link_download": f"{base_url}/download/{file_id}",
        "scadenza": scadenza,
    }


# --- PAGINA DI DOWNLOAD: chiede la password prima di consegnare il file ---
@app.get("/download/{file_id}", response_class=HTMLResponse)
async def pagina_download(file_id: str):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT data_scadenza FROM files WHERE id = ?", (file_id,))
    risultato = c.fetchone()
    conn.close()

    if not risultato:
        raise HTTPException(status_code=404, detail="Link non valido o scaduto.")
    if datetime.now() > datetime.strptime(risultato[0], "%Y-%m-%d %H:%M:%S"):
        raise HTTPException(status_code=410, detail="Il link è scaduto.")

    return f"""<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>G-Transfer - Scarica File</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; padding: 20px; box-sizing: border-box; }}
.container {{ background: white; padding: 40px; border-radius: 20px; box-shadow: 0 15px 35px rgba(0,0,0,0.2); width: 100%; max-width: 380px; text-align: center; }}
input {{ width: 100%; box-sizing: border-box; padding: 14px; border: 2px solid #ddd; border-radius: 10px; margin-bottom: 14px; font-size: 15px; }}
button {{ background: #764ba2; color: white; border: none; padding: 15px; width: 100%; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; }}
button:hover {{ background: #5a3a7d; }}
#errore {{ color: #b91c1c; font-size: 13px; margin-top: 10px; display: none; }}
</style></head>
<body>
<div class="container">
<h2>🔒 Scarica File Cifrato</h2>
<p>Inserisci la password per decifrare e scaricare il file.</p>
<input type="password" id="password" placeholder="Password">
<button onclick="scarica()">Decifra e Scarica</button>
<div id="errore"></div>
</div>
<script>
async function scarica() {{
    const password = document.getElementById('password').value;
    const erroreDiv = document.getElementById('errore');
    erroreDiv.style.display = "none";
    if (!password) {{ alert("Inserisci la password."); return; }}

    const formData = new FormData();
    formData.append("password", password);

    const risposta = await fetch("/scarica/{file_id}", {{ method: "POST", body: formData }});
    if (!risposta.ok) {{
        const dati = await risposta.json().catch(() => ({{}}));
        erroreDiv.textContent = dati.detail || "Errore durante lo scaricamento.";
        erroreDiv.style.display = "block";
        return;
    }}

    const blob = await risposta.blob();
    const nomeFile = risposta.headers.get("X-Nome-File") || "file_scaricato";
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = nomeFile; document.body.appendChild(a); a.click(); a.remove();
    window.URL.revokeObjectURL(url);
}}
</script>
</body></html>"""


# --- LOGICA DI DECIFRATURA E CONSEGNA DEL FILE ---
@app.post("/scarica/{file_id}")
async def scarica_file(file_id: str, password: str = Form(...)):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT nome_originale, data_scadenza, salt_b64 FROM files WHERE id = ?", (file_id,))
    risultato = c.fetchone()
    conn.close()

    if not risultato:
        raise HTTPException(status_code=404, detail="Link non valido o scaduto.")

    nome_originale, data_scadenza, salt_b64 = risultato

    if datetime.now() > datetime.strptime(data_scadenza, "%Y-%m-%d %H:%M:%S"):
        raise HTTPException(status_code=410, detail="Il link è scaduto.")

    percorso_fisico = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(percorso_fisico) or not salt_b64:
        raise HTTPException(status_code=404, detail="File non trovato sul server.")

    with open(percorso_fisico, "rb") as f:
        contenuto_cifrato = f.read()

    salt = base64.b64decode(salt_b64)
    chiave = deriva_chiave(password, salt)

    try:
        contenuto_decifrato = Fernet(chiave).decrypt(contenuto_cifrato)
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Password errata.")

    return Response(
        content=contenuto_decifrato,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{nome_originale}"',
            "X-Nome-File": nome_originale,
        },
    )


if __name__ == "__main__":
    import uvicorn
    # Render assegna la porta tramite la variabile d'ambiente PORT: se non è
    # presente (es. quando lo avvii in locale) si usa 8000 come prima.
    porta = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=porta)
