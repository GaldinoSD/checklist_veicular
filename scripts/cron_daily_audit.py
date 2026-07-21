#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de execução automática do diagnóstico do sistema (audit).
Pode ser agendado diretamente no Crontab do Linux:
0 7 * * * /var/www/checklist_veicular/venv/bin/python /var/www/checklist_veicular/scripts/cron_daily_audit.py
"""
import os
import sys

# Adiciona o diretório raiz do projeto ao PYTHONPATH
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from backend.blueprints.technical import execute_system_audit
from backend.models import Log, db
from backend.utils import agora

def run_cron_audit():
    with app.app_context():
        now_dt = agora()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now_str}] 🚀 Executando Diagnóstico/Auditoria Automática das 07:00h...")
        try:
            result = execute_system_audit()
            log_entry = Log(
                usuario="CRON (Automação 07:00h)",
                acao=f"Diagnóstico Automático das 07:00h concluído: {result}"
            )
            db.session.add(log_entry)
            db.session.commit()
            print(f"[{now_str}] ✅ Auditoria concluída com sucesso: {result}")
        except Exception as e:
            print(f"[{now_str}] ❌ Erro ao executar auditoria automática: {e}")

if __name__ == "__main__":
    run_cron_audit()
