from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import FileResponse, HTMLResponse
import shutil
import os
import uuid
import sqlite3
from datetime import datetime, timedelta

app = FastAPI()

# --- CONFIGURAZIONE ---
UPLOAD_DIR = "uploads"
DB_NAME = "trasferimenti.db"
# --- QUI SCEGLI LA TUA PASSWORD ---
PASSWORD_SEGRETA = "093121048" 

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
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    ora_attuale = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id FROM files WHERE data_scadenza < ?", (ora_attuale,))
    scaduti = c.fetchall()
    
    for row in scaduti:
        file_id = row[0]
        if os.path.exists(UPLOAD_DIR):
            for f in os.listdir(UPLOAD_DIR):
                if f.startswith(file_id):
                    try:
                        os.remove(os.path.join(UPLOAD_DIR, f))
                    except:
                        pass
        c.execute("DELETE FROM files WHERE id = ?", (file_id,))
    
    conn.commit()
    conn.close()

@app.get("/", response_class=HTMLResponse)
async def home():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>File index.html non trovato!</h1>"

@app.post("/upload")
async def carica_file(password: str = Form(...), file: UploadFile = File(...)):
    if password != PASSWORD_SEGRETA:
        raise HTTPException(status_code=403, detail="Password errata!")

    pulizia_file_scaduti()
    
    file_id = str(uuid.uuid4())
    nome_salvato = f"{file_id}_{file.filename}"
    percorso = os.path.join(UPLOAD_DIR, nome_salvato)
    
    with open(percorso, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    scadenza = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO files VALUES (?, ?, ?)", (file_id, file.filename, scadenza))
    conn.commit()
    conn.close()
    
    return {
        "link_download": f"https://mio-transfer-1.onrender.com/download/{file_id}",
        "scadenza": scadenza
    }

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
        raise HTTPException(status_code=404, detail="File non trovato.")

    return FileResponse(
        path=os.path.join(UPLOAD_DIR, nome_file_fisico),
        filename=nome_originale,
        media_type='application/octet-stream'
    )
