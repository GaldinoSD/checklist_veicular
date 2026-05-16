# 📘 TECH STACK OVERVIEW 2026: Checklist Veicular & Gestão Técnica

Este documento detalha a arquitetura, tecnologias e dependências utilizadas no desenvolvimento do sistema, servindo como blueprint para futuros projetos de alta performance.

---

## 1. Visão Geral da Arquitetura
O sistema segue um padrão **Monolítico Progressivo** baseado em Flask. Embora seja um monolito, ele utiliza uma **API REST Interna** (endpoints JSON) para alimentar componentes dinâmicos do frontend, garantindo uma experiência de usuário (UX) fluida sem recarregamentos constantes (estilo SPA em partes críticas).

- **Linguagem Core**: Python 3.10+
- **Arquitetura**: MVC (Model-View-Controller) simplificada.
- **Renderização**: Server-Side Rendering (SSR) com Jinja2 + Client-Side Dynamic Updates (AJAX/Fetch).

---

## 2. Stack de Backend (O Cérebro)

### Framework e Servidor
- **Flask (v3.0.3)**: Micro-framework robusto e escalável.
- **SQLAlchemy (v3.1.1)**: ORM (Object-Relational Mapping) para abstração completa do banco de dados.
- **Flask-Login (v0.6.3)**: Gestão de sessões e autenticação segura.
- **Werkzeug**: Utilizado para segurança de senhas (PBKDF2 com salt) e manipulação segura de arquivos.

### Processamento e Utilitários
- **ReportLab (v4.2.5)**: Biblioteca profissional para geração de PDFs complexos (Layouts, Tabelas, Gráficos).
- **Pillow / PIL (v10.4.0)**: Processamento e otimização de imagens (upload de vistorias).
- **pytz & holidays**: Precisão absoluta em fusos horários e detecção de feriados brasileiros para escalas.

---

## 3. Banco de Dados (A Fundação)
- **PostgreSQL**: Utilizado pela sua robustez, suporte a tipos de dados complexos (JSONB) e alta performance em concorrência.
- **Estrutura**: +30 modelos de dados cobrindo desde Frota (Veículos, Checklists) até Gestão Técnica (Scales, RFO, LMS, Geradores).

---

## 4. Stack de Frontend (A Experiência)

### Design & Estética (Premium UI)
- **Tailwind CSS (v3/v4)**: Utilizado via CDN customizado para agilidade e consistência visual.
- **Design System**: Baseado em *Glassmorphism* (transparência, desfoque e sombras profundas).
- **Tipografia**: Google Fonts - **Outfit** (Moderna e altamente legível).
- **Iconografia**: FontAwesome 6 Pro (Solid/Regular).

### Interatividade e Visualização
- **Chart.js (v4.4.1)**: Motor de gráficos para Dashboards (Linha, Doughnut, Barra).
- **Litepicker**: Seletor de datas moderno e responsivo para relatórios.
- **Vanilla JS (ES6+)**: Lógica de frontend pura, evitando o overhead de frameworks pesados, garantindo carregamento instantâneo.

---

## 5. Segurança e Governança
- **RBAC (Role-Based Access Control)**: Sistema de permissões granulares por usuário/módulo.
- **Logs de Auditoria**: Registro de todas as ações críticas no sistema para rastreabilidade.
- **Variáveis de Ambiente**: Proteção de credenciais sensíveis via arquivo `.env`.

---

## 6. Lista de Dependências (requirements.txt)
```text
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
reportlab==4.2.5
Pillow==10.4.0
python-dotenv
pytz
holidays
psycopg2-binary  # Driver PostgreSQL
```

---

## 7. Estrutura de Diretórios Recomendada
```text
/
├── app.py              # Aplicação principal
├── .env                # Configurações sensíveis
├── static/             # Ativos estáticos
│   ├── css/            # Estilos customizados
│   ├── img/            # Logo e ícones
│   ├── uploads/        # Fotos e evidências
├── templates/          # Arquivos HTML (Jinja2)
│   ├── layout.html     # Base comum (Shell)
│   ├── dashboard.html  # Dashboards Cockpit
│   └── components/     # Modais e fragmentos
└── instance/           # Dados da instância (se local)
```

---
> **Nota de Implementação**: Para replicar este sucesso em novos projetos, priorize o uso de **PostgreSQL** e a biblioteca **Chart.js** integrada com endpoints JSON do Flask. Isso garante a performance de "Cockpit" que o sistema atual possui.
