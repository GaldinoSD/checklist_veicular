import os
import pytz
from pathlib import Path
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

# Caminho raiz do projeto (uma pasta acima de /backend)
BASE_DIR = Path(__file__).resolve().parent.parent

# Timezone
TZ = pytz.timezone("America/Sao_Paulo")

# Intervalos e janelas de revisões
REV_INTERVAL = 10000
REV_ALERT_MARGIN = 500
WEEKS_WINDOW = 4

# Extensões de arquivo permitidas para uploads
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".webp"}

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "chave-secreta-padrao")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB
    
    # URI do Banco de Dados
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    
    # Opções do motor SQLAlchemy
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True
    }

# Caminhos de Uploads e Diretórios ajustados para o frontend
VISTORIAS_UPLOAD_DIR = BASE_DIR / "frontend" / "static" / "vistorias_fotos"
AVARIAS_UPLOAD_DIR = BASE_DIR / "frontend" / "static" / "avarias_fotos"
TREINAMENTOS_UPLOAD_DIR = BASE_DIR / "frontend" / "static" / "uploads" / "treinamentos"
UPLOAD_DIR = BASE_DIR / "frontend" / "static" / "checklist_fotos"
LAYOUT_UPLOAD_DIR = BASE_DIR / "frontend" / "static" / "uploads" / "layout"
LOGO_PATH = BASE_DIR / "frontend" / "static" / "logo.png"

INBOX_DIR = BASE_DIR / "inbox"
RELATORIOS_DIR = BASE_DIR / "relatorios"
