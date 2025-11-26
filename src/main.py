from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
import psutil
import asyncio
import json
import httpx
import os

app = FastAPI(title="Home Network IDS/IDP")

app.mount("/static", StaticFiles(directory="static"), name="static")

# Simple in-memory alert store
alerts = []
connected_websockets = []

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:1b"

async def analyze_with_ai(event: str):
    prompt = f"Analyze this network event and respond ONLY in JSON with severity (Low/Medium/High/Critical), threat_type, and short description:\n{event}"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(OLLAMA_URL, json={"model": MODEL, "prompt": prompt, "stream": False})
            result = resp.json()["response"]
            # Try to extract JSON
            start = result.find("{")
            end = result.rfind("}") + 1
            if start != -1 and end > 0:
                return json.loads(result[start:end])
        except:
            pass
    return {"severity": "Medium", "threat_type": "Unknown", "description": event}

@app.get("/", response_class=HTMLResponse)
async def root():
    with open("src/static/index.html") as f:
        return f.read()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)

async def broadcast_alert(alert):
    data = json.dumps(alert)
    for ws in connected_websockets[:]:
        try:
            await ws.send_text(data)
        except:
            connected_websockets.remove(ws)

async def monitor_network():
    seen = set()
    while True:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.status == 'ESTABLISHED':
                key = (conn.raddr.ip, conn.raddr.port)
                if key not in seen:
                    seen.add(key)
                    event = f"New connection from {conn.raddr.ip}:{conn.raddr.port} to local port {conn.laddr.port}"
                    analysis = await analyze_with_ai(event)
                    alert = {
                        "id": len(alerts),
                        "time": __import__('time').strftime("%H:%M:%S"),
                        "ip": conn.raddr.ip,
                        "port": conn.raddr.port,
                        "local_port": conn.laddr.port,
                        **analysis
                    }
                    alerts.append(alert)
                    if len(alerts) > 100:
                        alerts.pop(0)
                    await broadcast_alert(alert)
        await asyncio.sleep(2)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(monitor_network())

if __name__ == "__main__":
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=False)
