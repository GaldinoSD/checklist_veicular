# -*- coding: utf-8 -*-
"""
Ponto de entrada do Painel de Gerenciamento de Frota.
Expõe 'app', 'db' e todos os modelos para manter compatibilidade retroativa
com scripts externos, crons, e testes unitários.
"""
from backend import create_app, db
from backend.models import (
    User, Vehicle, VehicleInfo, VehicleMov, Checklist, ChecklistItem,
    Announcement, AnnouncementRead, Manual, ToolCategory, Tool, UserToolInspection,
    UserToolStatus, ToolSuggestion, Training, TrainingCourse, TrainingModule,
    TrainingQuestion, TrainingAssignment, TrainingAttempt, Badge, Generator,
    RFO, Solicitacao, SupervisaoTecnica, RotaExata, Team, Task, Patio, Encerramento,
    Scale, Meeting, Note, Activity, SystemRule, Company, Contract, ExternalCollaborator,
    AvariaOS, Log, Vistoria, VistoriaFoto, SystemConfig, WhatsAppConfig,
    NetworkNode, NetworkSplitter, NetworkEdge, GPSDevice, GPSLog
)

app = create_app()

# Expose helper functions for backward compatibility with unit tests and external scripts
from backend.utils import agora, manutencao_only, send_whatsapp_message
from backend.blueprints.auth import get_default_perms
from backend.blueprints.technical import api_gestao_treinamentos_lms_list as api_training_list

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
