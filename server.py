from pki_gui_tool.server.main import app

if __name__ == "__main__":
    import os
    import uvicorn

    host = os.getenv("PKI_SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("PKI_SERVER_PORT", "8765"))
    uvicorn.run(app, host=host, port=port)
