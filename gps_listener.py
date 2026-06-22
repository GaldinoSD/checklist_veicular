import asyncio
import socket
import logging
from datetime import datetime
from backend import create_app, db
from backend.models import GPSLog, GPSDevice, Vehicle
app = create_app()

# Configuração de Logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GPS_LISTENER")

PORT = 5002

def parse_tk103(data):
    """
    Decodifica o protocolo básico TK103.
    Exemplo: (012345678901234BP050000123456789012345GPRMC,123456.00,A,2331.1234,S,04631.1234,W,0.00,0.00,160526,,,A*7B)
    """
    try:
        raw = data.decode('utf-8', errors='ignore')
        # Regex ou split para extrair IMEI e GPRMC
        # IMEI costuma estar no início da mensagem
        imei = raw[1:16] # Exemplo simplificado
        if "GPRMC" in raw:
            parts = raw.split(',')
            lat_raw = parts[3]
            lat_dir = parts[4]
            lon_raw = parts[5]
            lon_dir = parts[6]
            speed = float(parts[7]) if parts[7] else 0
            
            # Conversão simples de coordenadas (Graus/Minutos para Decimal)
            lat = (float(lat_raw[:2]) + float(lat_raw[2:]) / 60) * (-1 if lat_dir == 'S' else 1)
            lon = (float(lon_raw[:3]) + float(lon_raw[3:]) / 60) * (-1 if lon_dir == 'W' else 1)
            
            return {
                "imei": imei,
                "lat": lat,
                "lon": lon,
                "speed": speed * 1.852, # Nós para Km/h
                "ignition": "ACC ON" in raw or "power on" in raw
            }
    except Exception as e:
        logger.error(f"Erro ao parsear dados: {e}")
    return None

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logger.info(f"Conexão recebida de {addr}")
    
    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            
            logger.debug(f"Dados brutos: {data}")
            parsed = parse_tk103(data)
            
            if parsed:
                with app.app_context():
                    device = GPSDevice.query.filter_by(imei=parsed['imei']).first()
                    log = GPSLog(
                        imei=parsed['imei'],
                        vehicle_id=device.vehicle_id if device else None,
                        lat=parsed['lat'],
                        lon=parsed['lon'],
                        speed=parsed['speed'],
                        ignition=parsed['ignition'],
                        raw_data=data.decode('utf-8', errors='ignore')
                    )
                    db.session.add(log)
                    db.session.commit()
                    logger.info(f"Log gravado para IMEI {parsed['imei']}")
            
            # Resposta opcional (depende do firmware do rastreador)
            # writer.write(b"ON")
            # await writer.drain()
            
    except Exception as e:
        logger.error(f"Erro na conexão {addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info(f"Conexão encerrada com {addr}")

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', PORT)
    logger.info(f"Servidor GPS TK103 iniciado na porta {PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
