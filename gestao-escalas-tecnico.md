# Plano de Implementação: Visualização de Plantões do Técnico e Notificações de Escala

Este plano detalha a implementação da visualização de plantões para técnicos (com botão no sidebar abrindo modal moderno/rápido) e a automação de notificações em tempo real (interna no sistema + WhatsApp) para qualquer ajuste ou agendamento na escala.

## Overview
1. Criar endpoint `/api/tecnico/minhas-escalas` para listar os plantões onde o usuário logado está escalado (diretamente ou via equipe), divididos em futuros e histórico, com estatísticas do mês.
2. Adicionar no sidebar (`layout.html`) o botão "Meus Plantões" com badge informativo e abrir um modal moderno/drawer elegante acessível de qualquer página.
3. Implementar módulo de notificação (`notify_technicians_scale_update` / `notify_technicians_scale_delete`) disparando `Announcement` (notificação interna com sininho e contador não lido) e `send_whatsapp_message` (Evolution API) sempre que uma escala for criada, editada ou removida.
4. Integrar com `api_escalas` e com `sync_annual_schedule_to_db_scales` para cobrir escalas avulsas e cronogramas anuais.

## Project Type
WEB

## Success Criteria
- [x] Endpoint `/api/tecnico/minhas-escalas` funcional com suporte a técnicos diretos e técnicos de equipes escaladas.
- [x] Botão "Meus Plantões" presente no sidebar sob o grupo "Operacional" para técnicos e usuários com acesso.
- [x] Modal moderno, responsivo e sem roxo/violeta (Purple Ban compliance) exibindo próximos plantões e histórico.
- [x] Criação e edição de escala disparam `Announcement` para o técnico afetado no sistema.
- [x] Notificação via WhatsApp enviada ao técnico se o mesmo possuir telefone cadastrado e o WhatsApp estiver ativo.
- [x] Exclusão de escala notifica o técnico sobre o cancelamento do plantão.
- [x] Testes automatizados cobrindo a rota de listagem e a emissão de notificações.

## Tech Stack
- Backend: Flask, SQLAlchemy, Python 3.10+
- Frontend: HTML5, Tailwind CSS, Vanilla JS, FontAwesome
- Canais de Alerta: Announcement (banco de dados) + WhatsApp (Evolution API em background thread)

## File Structure
- `backend/blueprints/technical.py`: Endpoints `/api/tecnico/minhas-escalas`, lógicas de notificação e ganchos em `api_escalas` e `sync_annual_schedule_to_db_scales`.
- `backend/models/__init__.py`: Permissão padrão em `has_permission` para `meus_plantoes`.
- `frontend/templates/layout.html`: Botão no sidebar, modal moderno "Meus Plantões", estilos e scripts JS.
- `tests/test_meus_plantoes_notifications.py`: Suíte de testes unitários e de integração.
