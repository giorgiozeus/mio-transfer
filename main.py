from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
import shutil
import os
import uuid
import sqlite3
from datetime import datetime, timedelta

app = FastAPI()

# --- CONFIGURAZIONE INIZIALE ---
UPLOAD_DIR = "uploads"
DB_NAME = "trasferimenti.db"

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (id TEXT PRIMARY KEY, nome_originale TEXT, data_scadenza TEXT)''')
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
        # Elimina il file fisico se esiste
        if os.path.exists(UPLOAD_DIR):
            for f in os.listdir(UPLOAD_DIR):
                if f.startswith(file_id):
                    try:
                        os.remove(os.path.join(UPLOAD_DIR, f))
                    except:
                        pass
        # Elimina dal DB
        c.execute("DELETE FROM files WHERE id = ?", (file_id,))
    
    conn.commit()
    conn.close()

# --- INTERFACCIA UTENTE ---
@app.get("/", response_class=HTMLResponse)
async def home():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>File index.html non trovato! Assicurati che sia nella stessa cartella.</h1>"

# --- LOGICA DI CARICAMENTO (UPLOAD) ---
@app.post("/upload")
async def carica_file(file: UploadFile = File(...)):
    # Ad ogni nuovo upload, puliamo i vecchi file scaduti
    pulizia_file_scaduti()
    
    file_id = str(uuid.uuid4())
    nome_salvato = f"{file_id}_{file.filename}"
    percorso = os.path.join(UPLOAD_DIR, nome_salvato)
    
    with open(percorso, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Scadenza a 7 giorni (puoi cambiare in timedelta(hours=1) per testare subito)
    scadenza = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO files VALUES (?, ?, ?)", (file_id, file.filename, scadenza))
    conn.commit()
    conn.close()
    
    return {
        "link_download": f"http://localhost:8000/download/{file_id}",
        "scadenza": scadenza
    }

# --- LOGICA DI SCARICAMENTO (DOWNLOAD) ---
@app.get("/download/{file_id}")
async def scarica_file(file_id: str):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT nome_originale, data_scadenza FROM files WHERE id = ?", (file_id,))
    risultato = c.fetchone()
    conn.close()

    if not risultato:
        raise HTTPException(status_code=404, detail="Link non valido o scaduto.")

    nome_originale, data_scadenza = risultato
    
    if datetime.now() > datetime.strptime(data_scadenza, "%Y-%m-%d %H:%M:%S"):
        raise HTTPException(status_code=410, detail="Il link è scaduto.")

    files = os.listdir(UPLOAD_DIR)
    nome_file_fisico = next((f for f in files if f.startswith(file_id)), None)

    if not nome_file_fisico:
        raise HTTPException(status_code=404, detail="File non trovato sul server.")

    return FileResponse(
        path=os.path.join(UPLOAD_DIR, nome_file_fisico),
        filename=nome_originale,
        media_type='application/octet-stream'
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)