# 🏛️ Blueprint Arquitetural & Guia de Estilo Base

> **Manual de Engenharia e Design System**  
> Documento consolidado contendo linguagens, padrões visuais, componentes, modais, divisão de diretórios e boas práticas para reutilização deste ecossistema como boilerplate/base para novos projetos.

---

## 1. 🔤 Linguagens e Tecnologias Principais

| Camada | Tecnologia / Linguagem | Versão / Padrão | Utilização no Sistema |
| :--- | :--- | :--- | :--- |
| **Backend** | **Python** | 3.10+ | Lógica de negócios, API REST interna, ORM, manipulação de arquivos e jobs em segundo plano. |
| **Frontend - Marcação** | **HTML5 + Jinja2** | HTML5 Semântico | Renderização SSR (Server-Side Rendering) integrada a componentes reutilizáveis e herança via `{% extends "layout.html" %}`. |
| **Frontend - Estilização** | **CSS3 + Tailwind CSS** | Tailwind via CDN + CSS Custom Properties | Sistema de design utility-first, modo escuro nativo (`dark`), glassmorphism e estilização customizada de inputs e tabelas. |
| **Frontend - Scripts** | **JavaScript Vanilla** | ECMAScript 2022+ (ES6+) | Lógica de interface reativa, manipulação de DOM, interceptor global de requisições `fetch`, OCR e canvas. Zero frameworks pesados (sem React/Vue), garantindo carregamento instantâneo. |
| **Banco de Dados** | **SQL (PostgreSQL / SQLite)** | PostgreSQL em prod / SQLite em dev | Armazenamento relacional com suporte a tipos complexos, chaves estrangeiras e integridade referencial. |
| **Geração de Documentos** | **ReportLab / Pillow** | 4.2.5 / 10.4.0 | Renderização e exportação programática de relatórios em PDF com formatação visual e imagens. |
| **Infra & Servidor** | **Gunicorn + Nginx + Bash** | WSGI Server | Servidor de aplicação Python em produção com proxy reverso e SSL. |

---

## 2. 🎨 Identidade Visual e Design System

O sistema adota uma estética **moderna, corporativa e limpa** com inspiração em dashboards SaaS de alta densidade de informação (Cockpit UI).

### 2.1 Tipografia
* **Família Primária**: `Plus Jakarta Sans`, combinada com `Inter` e fontes de sistema (`-apple-system`, `BlinkMacSystemFont`, `sans-serif`).
* **Importação Google Fonts**:
  ```html
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  ```
* **Características**: Excelente legibilidade em telas de alta densidade, caracteres numéricos bem balanceados para tabelas e métricas.

### 2.2 Cores e Variáveis Dinâmicas (White-Label)
O sistema implementa **CSS Custom Properties** injetadas dinamicamente pelo banco de dados no cabeçalho do `layout.html`. Isso permite trocar as cores da marca em tempo de execução sem recompilar CSS:

```css
:root {
  --brand-primary: #10b981;    /* Cor de destaque primária (ex: Emerald 500) */
  --brand-secondary: #064e3b;  /* Tom secundário / contraste profundo */
  --brand-radius: 12px;        /* Arredondamento padrão de botões e cartões */
}
```

### 2.3 Modo Escuro (Dark Mode Híbrido)
* **Estratégia**: Baseada na classe `dark` aplicada diretamente no elemento `<html>`.
* **Detecção Automática**: Respeita a preferência do sistema operacional (`prefers-color-scheme: dark`) com persistência em `localStorage`:
  ```javascript
  (function () {
    try {
      const saved = localStorage.getItem("theme");
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const shouldDark = saved ? (saved === "dark") : prefersDark;
      if (shouldDark) document.documentElement.classList.add("dark");
      else document.documentElement.classList.remove("dark");
    } catch (e) {}
  })();
  ```
* **Paleta de Fundos e Superfícies**:
  * **Modo Claro**: Fundo geral `#f8fafc` (Slate 50), cartões `#ffffff` com bordas sutis `border-slate-200/80`.
  * **Modo Escuro**: Fundo geral `#0b0f19` / `#0f172a`, cartões `#1e293b` ou `#0d131f` com bordas translúcidas `border-white/5`.

### 2.4 Sombras e Efeitos Visuais
Definidos via extensão do tema Tailwind:
```javascript
tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      boxShadow: {
        subtle: "0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)",
        card: "0 4px 6px -1px rgba(0, 0, 0, 0.04), 0 2px 4px -2px rgba(0, 0, 0, 0.03)",
        dropdown: "0 12px 30px -4px rgba(0, 0, 0, 0.08), 0 4px 6px -2px rgba(0, 0, 0, 0.04)",
        glass: "0 18px 60px rgba(0,0,0,.35)",
      }
    }
  }
}
```

---

## 3. 🧩 Componentes Interativos e Bibliotecas

| Biblioteca | Versão / Fonte | Finalidade |
| :--- | :--- | :--- |
| **FontAwesome** | 6.5.1 (CDNJS) | Toda a iconografia do sistema (ações, menus, status, badges). |
| **Chart.js** | 4.4.1 (jsDelivr) | Gráficos dinâmicos nos Dashboards (barras, linhas, rosquinhas/doughnut). |
| **Litepicker** | 2.x (jsDelivr) | Seletores de intervalo de datas (Data Início / Data Fim) leves e responsivos. |
| **FullCalendar** | 6.1.11 (jsDelivr) | Calendário completo para escalas, plantões, reuniões e eventos. |
| **Leaflet & MarkerCluster** | 1.9.4 / 1.4.1 | Mapas interativos para rastreamento de frotas e geolocalização. |
| **Tesseract.js** | 5.x (jsDelivr) | OCR direto no navegador para leitura óptica de placas e hodômetros em fotos. |
| **Canvas HTML5** | Nativo | Coleta de assinaturas digitais com o dedo/mouse direto na tela sem plugins externos. |

---

## 4. 🪟 Arquitetura de Modais e Toasts

O sistema utiliza um padrão **zero dependências** para modais e notificações, garantindo máxima velocidade e total controle do estilo.

### 4.1 Padrão de Modal (Tailwind + Backdrop Blur)
Estrutura HTML padrão:
```html
<!-- Modal Container -->
<div id="meuModal" class="fixed inset-0 hidden items-center justify-center z-[100] p-4">
  <!-- Fundo com desfoque e escurecimento -->
  <div class="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onclick="closeModal('meuModal')"></div>
  
  <!-- Corpo do Modal -->
  <div class="relative bg-white dark:bg-slate-900 rounded-2xl shadow-dropdown border border-slate-200 dark:border-slate-800 w-full max-w-lg p-6 overflow-hidden">
    <!-- Cabeçalho -->
    <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
      <h3 class="text-base font-bold text-slate-800 dark:text-white flex items-center gap-2">
        <i class="fa-solid fa-layer-group text-emerald-500"></i> Título do Modal
      </h3>
      <button onclick="closeModal('meuModal')" class="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>

    <!-- Conteúdo -->
    <div class="py-4 text-sm text-slate-600 dark:text-slate-300">
      Conteúdo do formulário ou informações.
    </div>

    <!-- Rodapé de Ações -->
    <div class="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800">
      <button type="button" onclick="closeModal('meuModal')" class="px-4 py-2 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all">
        Cancelar
      </button>
      <button type="submit" class="btn-primary px-5 py-2 text-xs font-semibold rounded-xl text-white">
        Confirmar
      </button>
    </div>
  </div>
</div>
```

Funções JavaScript controladoras:
```javascript
function openModal(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.remove('hidden');
    el.classList.add('flex');
    el.style.display = 'flex';
  }
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.add('hidden');
    el.classList.remove('flex');
    el.style.display = 'none';
  }
}
```

### 4.2 Sistema de Notificações Toast com Barra de Progresso
* **Elemento Host**: `<div id="toast-container" class="fixed bottom-5 right-5 z-[200] flex flex-col gap-2"></div>`
* **Comportamento**: Entra deslizando da direita (`translateX`), exibe ícone semântico (sucesso, erro, alerta, info) e possui uma barra de tempo linear que some automaticamente após 4 segundos.
* **Disparo**:
  ```javascript
  showToast("Operação realizada com sucesso!", "success"); // ou "error", "warning", "info"
  ```
* **Integração com Backend**: Flash messages do Flask (`get_flashed_messages()`) são convertidas automaticamente em Toasts no carregamento da página.

---

## 5. 📁 Estrutura e Divisão de Pastas

Esta organização separa responsabilidades de forma clara (**Clean Modular Monolith**):

```text
meu_novo_projeto/
│
├── app.py                     # Entry point do aplicativo (inicializa app, db e expõe objetos)
├── wsgi.py                    # Ponto de entrada para servidores WSGI (Gunicorn / uWSGI)
├── requirements.txt           # Lista de dependências Python
├── .env                       # Variáveis de ambiente (SECRET_KEY, DATABASE_URL, etc.)
│
├── backend/                   # 🧠 NÚCLEO DO BACKEND (Lógica, Modelos e Serviços)
│   ├── __init__.py            # Application Factory (create_app), injeção de CSRF, filtros Jinja2
│   ├── config.py              # Configurações do Flask e caminhos de diretórios (BASE_DIR)
│   ├── utils.py               # Funções utilitárias (datas BR, autenticação, logs, envio de msgs)
│   ├── scheduler.py           # Agendador de tarefas em background (auditorias automáticas, cron)
│   │
│   ├── models/                # 🗄️ MODELOS DE DADOS (SQLAlchemy ORM)
│   │   └── __init__.py        # Definição das tabelas (Users, Permissões, Logs, Entidades de Domínio)
│   │
│   └── blueprints/            # 🚦 ROTAS E CONTROLADORES (Blueprints modulares)
│       ├── auth.py            # Login, Logout, RBAC, Troca de Senha, Gerenciamento de Usuários
│       ├── core.py            # Rotas principais, Dashboard, Notificações e Configurações Globais
│       └── [modulo].py        # Blueprints específicos do domínio (ex: produtos, estoque, etc.)
│
├── frontend/                  # 💻 NÚCLEO DO FRONTEND (Templates e Ativos Estáticos)
│   ├── templates/             # Arquivos HTML Jinja2
│   │   ├── layout.html        # Shell global (Topbar, Sidebar responsiva, Modais globais, Toasts)
│   │   ├── login.html         # Tela de autenticação moderna e isolada
│   │   ├── dashboard.html     # Painel principal com gráficos Chart.js e métricas
│   │   ├── users.html         # Gestão de usuários e permissões (tabelas e filtros)
│   │   └── components/        # Fragmentos reutilizáveis (se necessário)
│   │
│   └── static/                # Ativos servidos pelo servidor web
│       ├── favicon.ico        # Ícone do site
│       ├── logo.png           # Logotipo da empresa
│       └── uploads/           # Diretório para fotos, anexos e mídias enviadas por usuários
│
├── tests/                     # 🧪 TESTES AUTOMATIZADOS
│   ├── test_auth.py           # Testes de login e permissões
│   └── test_api.py            # Testes de endpoints JSON
│
└── scratch/                   # Scripts temporários ou migrações manuais
```

---

## 6. 🛡️ Segurança e Padrões Globais Integrados

1. **Proteção Anti-CSRF Universal**:
   * Token gerado na sessão e disponibilizado em `<meta name="csrf-token" content="{{ csrf_token }}">`.
   * **Injetor Automático**: Qualquer `<form method="POST">` submetido ganha o input oculto de token automaticamente via JavaScript.
   * **Interceptor `window.fetch`**: Todo disparo AJAX via `fetch()` (POST, PUT, DELETE) adiciona automaticamente o cabeçalho `X-CSRFToken`.
2. **Controle de Acesso Granular (RBAC)**:
   * Cada usuário possui perfil (`admin`, `gestor`, `operador`) e um dicionário de permissões booleanas em JSON (ex: `can_edit_users`, `can_view_reports`).
   * Decorator customizado `@permission_required("modulo")` no backend.
3. **Cabeçalhos HTTP de Segurança**:
   * Adicionados nativamente em `@app.after_request`: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`.

---

## 7. 🚀 Passo a Passo para Criar um Novo Sistema Usando esta Base

### Passo 1: Clonar a Estrutura Base
Copie as pastas `backend/`, `frontend/`, `requirements.txt` e `app.py` para a nova pasta do seu projeto.

### Passo 2: Limpar os Modelos Antigos
No arquivo `backend/models/__init__.py`, mantenha os modelos fundamentais de infraestrutura:
* `User` (Autenticação e Permissões)
* `Log` (Auditoria de ações)
* `SystemConfig` (Customizações visuais e parâmetros do sistema)

Remova as tabelas que eram exclusivas de veículos/técnicos e crie as novas tabelas necessárias para o seu negócio.

### Passo 3: Limpar os Blueprints
Mantenha:
* `auth.py`: Autenticação e RBAC.
* Crie o seu blueprint principal (ex: `financeiro.py`, `vendas.py`, etc.) registrando-o em `backend/__init__.py`.

### Passo 4: Atualizar os Itens da Sidebar
No arquivo `frontend/templates/layout.html`:
* Localize `<nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto custom-scrollbar">`.
* Substitua os links do checklist/veículos pelos novos menus da sua aplicação mantendo a classe `.sidebar-link`.

### Passo 5: Inicializar o Ambiente
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
O sistema subirá imediatamente com interface profissional, dark mode, controle de permissões, modais responsivos e design pronto para produção.
