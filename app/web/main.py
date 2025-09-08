from fastapi import FastAPI
import socket, os, datetime
app = FastAPI()
VERSION = os.getenv("APP_VERSION","v0.1.0")

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/")
def root(): return {"msg":"hello","host":socket.gethostname()}

@app.get("/version")
def version(): return {"version": VERSION}

@app.get("/time")
def time(): return {"utc": datetime.datetime.utcnow().isoformat()+"Z"}

