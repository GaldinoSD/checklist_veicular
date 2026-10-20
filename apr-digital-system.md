# Plano de Implantação: APR Digital (Análise Preliminar de Riscos)

## Objetivo
Implantar o sistema digital de APR (Análise Preliminar de Riscos) para equipes operacionais de telecomunicações, cobrindo:
1. Interface do técnico em campo (mobile-first, identificação automática do técnico, equipe, perguntas dinâmicas NR-35/NR-10, fotos).
2. Painel de gerenciamento e acompanhamento para Segurança do Trabalho (TST) e supervisão.
3. Módulo de configuração de perguntas, categorias e critérios impeditivos.
4. Integração completa ao sidebar e RBAC (permissões de usuário).

---

## Tarefas de Execução

- [x] **Fase 1: Modelos de Dados & Migração de Banco**
  - Criar modelos `APR`, `APRMembro`, `APRResposta` e `APRItemConfig` em `backend/models/__init__.py`.
  - Configurar `ensure_min_schema()` em `backend/__init__.py` para criação automática de tabelas no PostgreSQL/SQLite.
  - Criar função de semente (seed) com perguntas regulamentares de SST Telecom (NR-35, NR-10, vias, EPIs).

- [x] **Fase 2: Permissões & RBAC**
  - Adicionar permissões `perm_apr_mobile`, `perm_apr_gerenciamento` e `perm_config_apr` no RBAC de `backend/models/__init__.py` e `backend/blueprints/auth.py`.
  - Conceder `perm_apr_mobile` por padrão para técnicos (`role == 'tech'`).

- [x] **Fase 3: Rotas & Lógica de Negócio (Backend)**
  - Implementar endpoints no blueprint técnico/frota:
    - `/apr`: Formulário mobile do técnico com dados pré-carregados.
    - `/api/apr/salvar`: Processamento da APR, upload de fotos, verificação de bloqueio impeditivo e cálculo de liberação.
    - `/gerenciamento/aprs`: Dashboard gerencial com filtros, métricas de SST e listagem.
    - `/api/apr/<int:id>`: Consulta dos dados completos e fotos da APR.
    - `/apr/<int:id>/pdf`: Emissão de laudo oficial em PDF.
    - `/configuracao/apr`: Gestão dos itens e perguntas da APR.
    - `/api/apr/config/item`: Criar/Editar/Excluir/Alternar itens da APR.

- [x] **Fase 4: Interface do Sidebar & Navegação**
  - Atualizar `frontend/templates/layout.html`:
    - Adicionar link "APR - Análise de Riscos" no menu **Operacional** para técnicos.
    - Adicionar link "APRs de Campo" no menu **Gerenciamento**.
    - Adicionar link "Configuração APR" no submenu **Configurações**.

- [x] **Fase 5: Interface Mobile do Técnico (`apr_mobile.html`)**
  - Desenvolver layout responsivo de alta usabilidade para celulares corporativos:
    - Identificação visual imediata do técnico logado.
    - Seleção rápida de membros da equipe técnica.
    - Perguntas-gatilho dinâmicas (NR-35, NR-10, Via Pública, Condições Climáticas).
    - Destaque para condições impeditivas com registro de medidas de controle e evidências fotográficas.
    - Assinatura/confirmação digital de ciência dos riscos.

- [x] **Fase 6: Painel Gerencial SST (`apr_gerenciamento.html`)**
  - Cockpit com indicadores visuais de SST (total de APRs, liberadas, bloqueadas, perigos mais frequentes).
  - Tabela filtrável com badges de status, membros da equipe, busca rápida e modal completo de auditoria com galeria de fotos.

- [x] **Fase 7: Painel de Configuração (`config_apr.html`)**
  - Abas por categoria de risco (Geral & EPI, Altura NR-35, Elétrica NR-10, Trânsito & Vias, Clima & Meio Ambiente).
  - Controle de ativação, obrigatoriedade de fotos e status de condição impeditiva.

- [x] **Fase 8: Testes Automatizados & Validação**
  - Criar testes unitários em `tests/test_apr.py` validando ciclo completo de APR, vínculo de técnicos, bloqueio impeditivo e liberação com medida de controle.
