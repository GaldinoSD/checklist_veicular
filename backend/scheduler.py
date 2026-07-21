# -*- coding: utf-8 -*-
"""
Scheduler de tarefas em segundo plano para o Checklist Veicular.
Executa a auditoria/diagnóstico de sistema automaticamente todos os dias às 07:00h.
"""
import threading
import time
from datetime import datetime
from backend.config import TZ

_audit_scheduler_started = False
_audit_lock = threading.Lock()
_last_audit_date = None

def start_audit_scheduler(app):
    """Inicia a thread em segundo plano responsável pelo agendamento diário das 07:00h."""
    global _audit_scheduler_started
    with _audit_lock:
        if _audit_scheduler_started:
            return
        _audit_scheduler_started = True

    def scheduler_loop():
        global _last_audit_date
        print("⏰ [Scheduler] Agendador de Auditoria Automática (07:00h) inicializado.")
        while True:
            try:
                time.sleep(20)  # Verifica o relógio a cada 20 segundos
                now = datetime.now(TZ)
                today_str = now.strftime("%Y-%m-%d")
                
                # Executa todo dia na janela das 07:00 AM (07:00:00 a 07:00:59)
                if now.hour == 7 and now.minute == 0:
                    if _last_audit_date != today_str:
                        with app.app_context():
                            from backend.blueprints.technical import execute_system_audit
                            from backend.models import Log, db
                            print(f"⏰ [AutoAudit] Executando auditoria/diagnóstico diário automático às {now.strftime('%H:%M:%S')}...")
                            result = execute_system_audit()
                            
                            try:
                                log_entry = Log(
                                    usuario="SISTEMA (Automação 07:00h)",
                                    acao=f"Auditoria Diária Automática das 07:00h concluída: {result}"
                                )
                                db.session.add(log_entry)
                                db.session.commit()
                            except Exception as log_err:
                                print("⚠️ Erro ao gravar log de auditoria automática:", log_err)
                                
                            _last_audit_date = today_str
            except Exception as e:
                print("⚠️ Erro no loop da auditoria automática:", e)
                time.sleep(10)

    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
