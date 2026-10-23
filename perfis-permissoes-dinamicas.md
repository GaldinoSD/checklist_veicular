# Plano de Ação: Gerenciador Dinâmico de Perfis de Acesso e Permissões

## Overview
Implementar um sistema completo e dinâmico de Perfis de Acesso na tela de Usuários e Permissões. Permitirá criar, editar, configurar permissões padrão por perfil, renomear identificadores com migração automática dos colaboradores, e excluir perfis de forma segura. O sistema manterá o modelo de permissões granulares por usuário para concessões extras de acesso, com sincronização em tempo real entre o perfil e os usuários associados.

## Project Type
WEB (Flask + Jinja2 + Tailwind CSS / Vanilla JS)

## Success Criteria
- [x] Modelo de banco de dados `AccessProfile` criado e integrado ao SQLAlchemy (`ensure_min_schema` e `seed_defaults`).
- [x] Perfis nativos iniciais (`admin`, `supervisor`, `tech`, `manutencao`) inicializados com suas permissões padrão.
- [x] Modelo `User.has_permission(perm)` atualizado para resolver permissões dinamicamente (perfil do banco + permissões granulares do usuário).
- [x] Rotas no backend:
  - `POST /perfis/novo` (Criar perfil com slug, nome, cor, descrição e matriz de permissões).
  - `POST /perfis/<id>/editar` (Editar perfil, incluindo renomeação de slug com migração atômica de `User.role`).
  - `POST /perfis/<id>/excluir` (Excluir perfil não-sistema, com validação de usuários associados).
  - `GET /api/perfis/<id>` (Dados e permissões do perfil em JSON para edição dinâmica).
  - Rotas de usuário (`users_new` e `users_role`) atualizadas para carregar e aceitar os perfis dinâmicos.
- [x] Interface `users.html` aprimorada:
  - Abas superiores elegantes: **Colaboradores** e **Perfis de Acesso**.
  - Painel de Perfis com cards visuais, badges coloridas, contagem de colaboradores vinculados e badges dos módulos liberados.
  - Modais dedicados: Novo Perfil e Editar Perfil com grid completo de permissões e botões "Marcar Todas" / "Desmarcar".
  - Dropdowns de perfil nos modais de Colaboradores renderizando a lista dinâmica de perfis do banco.
  - Zero uso de código de cor roxa/violeta (Purple Ban compliance).
- [x] Testes unitários/automatizados criados e validados com sucesso (`tests/test_perfis_dinamicos.py` e `tests/test_has_permission.py`).
- [x] Compatibilidade garantida com permissões granulares individuais preservadas.

## Tech Stack
- Backend: Python 3, Flask, Flask-SQLAlchemy, SQLite / PostgreSQL.
- Frontend: Jinja2, Tailwind CSS (utilitários existentes), FontAwesome 6, Vanilla JavaScript.

## File Structure & Dependencies
- `backend/models/__init__.py`: Modelo `AccessProfile`, propriedades e `User.has_permission`.
- `backend/__init__.py`: Criação de tabela em `ensure_min_schema()` e `seed_defaults()`.
- `backend/blueprints/auth.py`: Rotas CRUD de perfis e atualização de validações de usuários.
- `backend/utils.py`: Mapeamento de endpoints e regras de autorização.
- `frontend/templates/users.html`: Abas de alternância, gerenciador de perfis, modais de criação/edição.
- `tests/test_perfis_dinamicos.py`: Testes automatizados do novo fluxo.

## Task Breakdown
1. **Modelos & Banco de Dados**: Criar `AccessProfile`, atualizar `User` com propriedades dinâmicas e resolução híbrida perfil+granular.
2. **Inicialização & Schema**: Adicionar tabela `access_profile` em `ensure_min_schema` e perfis padrão em `seed_defaults`.
3. **Rotas Backend & API**: Implementar `/perfis/novo`, `/perfis/<id>/editar`, `/perfis/<id>/excluir` e `/api/perfis/<id>`. Atualizar `users_new` e `users_role`.
4. **Interface e Modais (Frontend)**: Atualizar `users.html` com abas, painel de perfis e modais estilizados.
5. **Testes & Validação**: Executar testes automatizados cobrindo criação, edição com renomeação de slug, deleção e herança de permissões.
6. **Deploy & Checagem Final**: Reiniciar gunicorn e auditar logs.
