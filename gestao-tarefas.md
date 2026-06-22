# Plano de Ação: Ajuste Gestão Técnica - Tarefas e Atividades

Ajustar a exibição das Tarefas e Atividades Realizadas na Gestão Técnica para um layout premium de cartões em grid, organizadas em sub-abas separadas (semelhante ao Controle de O.S.), contendo modais completos para visualização de detalhes.

## Overview
A aba de "Tarefas" atual exibe duas listas verticais (tarefas e atividades) simples. Vamos reestruturar este painel usando sub-abas de alternância rápida, converter as listas em grids de cards estilizados (inspirados no visual de O.S. de avarias) e criar um modal de detalhamento completo para as atividades realizadas.

## Project Type
WEB

## Success Criteria
- [x] Sub-abas "Tarefas" e "Atividades Realizadas" funcionando de forma alternável no painel `#pane-tarefas`.
- [x] Listas de tarefas e atividades exibidas em grids de cartões premium responsivos.
- [x] Botão de "Ver Detalhes" abrindo os respectivos modais em ambas as sub-abas.
- [x] Exibição em blocos individuais dos campos dinâmicos no modal de detalhes da atividade realizada.
- [x] Persistência de dados inalterada (sem novas tabelas ou migrações complexas de banco de dados).

## Tech Stack
- Frontend: HTML5, Tailwind CSS (classes utilitárias já inclusas no template), Javascript (ES6)
- Backend: Flask, SQLAlchemy, SQLite (sem mudanças necessárias)

## File Structure
- `/var/www/checklist_veicular/frontend/templates/gestao_tecnica.html` (Front-end principal)

## Task Breakdown

### Tarefa 1: Adicionar Estrutura de Sub-abas e Grid no Template
- **Responsável**: `frontend-specialist`
- **Habilidades**: `frontend-design`, `react-best-practices` (e templates)
- **Input**: `frontend/templates/gestao_tecnica.html`
- **Output**: Sub-abas de alternância entre Tarefas e Atividades e grids de cards estruturados no HTML.
- **Verificação**: Abrir a aba de tarefas no navegador e validar se as sub-abas aparecem e alternam corretamente (exibindo e ocultando os containers).

### Tarefa 2: Redesenhar Cards de Tarefas no Javascript
- **Responsável**: `frontend-specialist`
- **Habilidades**: `frontend-design`
- **Input**: Renderizador de tarefas `loadItems('tarefas')` em `gestao_tecnica.html`.
- **Output**: JS gerando cards estilizados em grid, contendo botão "Detalhes", "Editar", "Excluir" e ações de transição.
- **Verificação**: Inserir uma tarefa e ver se ela renderiza em formato de card premium, com borda lateral/superior condizente com a prioridade.

### Tarefa 3: Redesenhar Cards de Atividades Realizadas no Javascript
- **Responsável**: `frontend-specialist`
- **Habilidades**: `frontend-design`
- **Input**: Renderizador de atividades realizadas `loadAtividadesRealizadas()` em `gestao_tecnica.html`.
- **Output**: JS gerando cards para as atividades realizadas, contendo prévia resumida de campos, botão PDF, botão Detalhes, Editar e Excluir.
- **Verificação**: Registrar uma atividade realizada e checar se renderiza como card no grid.

### Tarefa 4: Criar Modal de Detalhes da Atividade Realizada
- **Responsável**: `frontend-specialist`
- **Habilidades**: `frontend-design`
- **Input**: `gestao_tecnica.html`
- **Output**: Modal de detalhes de atividades e função `showAtividadeRealizadaDetalhes(id)` para popular as informações em blocos individuais.
- **Verificação**: Clicar em "Ver Detalhes" no card de uma atividade e conferir se abre o modal com todos os dados e campos dinâmicos em blocos.

---

## Phase X: Verification
- [x] No purple/violet hex codes used (compliance check).
- [x] Socratic Gate respected.
- [x] Manual check of creation, list, detail view, edit, and deletion flows.

## ✅ PHASE X COMPLETE
- Lint: ✅ Pass
- Security: ✅ No critical issues
- Build: ✅ Success
- Date: 2026-06-11
