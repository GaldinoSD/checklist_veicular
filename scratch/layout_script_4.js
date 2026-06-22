
      // Toast Notification
      function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast toast-${type} shadow-2xl relative overflow-hidden`;
        
        const icons = {
            'success': 'fa-circle-check text-emerald-500',
            'error': 'fa-circle-xmark text-red-500',
            'info': 'fa-circle-info text-blue-500',
            'warning': 'fa-circle-exclamation text-amber-500'
        };
        const icon = icons[type] || icons.info;
        
        toast.innerHTML = `
          <i class="fa-solid ${icon} text-lg"></i>
          <span class="text-sm font-bold text-slate-800 dark:text-white">${message}</span>
          <div class="toast-progress">
            <div class="toast-progress-bar"></div>
          </div>
        `;
        
        container.appendChild(toast);
        setTimeout(() => toast.classList.add('show'), 10);
        
        setTimeout(() => {
          toast.classList.remove('show');
          setTimeout(() => toast.remove(), 400);
        }, 4000);
      }

      // Trigger Flashed Messages as Toasts
      
        
          window.addEventListener('DOMContentLoaded', () => {
            
              
                showToast("[]", "[]");
              
            
          });
        
      

      // Sidebar Logic
      (function() {
        const sidebar = document.getElementById('sidebar');
        const btnMobile = document.getElementById('btnMobileToggle');

        if (!sidebar) return;

        if (btnMobile) btnMobile.addEventListener('click', () => sidebar.classList.toggle('mobile-open'));
        
        document.addEventListener('click', (e) => {
          if (window.innerWidth <= 1024 && !sidebar.contains(e.target) && !btnMobile.contains(e.target)) {
            sidebar.classList.remove('mobile-open');
          }
        });
      })();

      // Modal Logic
      function openModal(id) {
        const el = document.getElementById(id);
        if(el) { el.classList.remove('hidden'); el.classList.add('flex'); }
      }
      function closeModal(id) {
        const el = document.getElementById(id);
        if(el) { el.classList.add('hidden'); el.classList.remove('flex'); }
      }

      // ✅ TOPBAR CLOCK
      function updateClock() {
        const now = new Date();
        const time = now.toLocaleTimeString('pt-BR', { hour12: false });
        const el = document.getElementById('topbar-clock');
        if (el) el.textContent = time;
      }
      setInterval(updateClock, 1000);
      updateClock();

      // ✅ SUBMENU TOGGLE
      function toggleSubmenu(id, btn) {
        const submenu = document.getElementById(id);
        if (submenu) {
          submenu.classList.toggle('open');
          const chevron = btn.querySelector('.chevron-rotate');
          if (chevron) chevron.classList.toggle('open-chevron');
        }
      }

      // ✅ GLOBAL TAB NAVIGATION HANDLER
      document.addEventListener('click', function(e) {
        const tabLink = e.target.closest('.sidebar-tab-link');
        if (tabLink && (window.location.pathname.includes('/gestao-tecnica') || window.location.pathname.includes('/gestao_tecnica'))) {
          e.preventDefault();
          const tabId = tabLink.getAttribute('data-tab');
          if (typeof switchTab === 'function') {
            switchTab(tabId);
            const url = new URL(window.location);
            url.searchParams.set('tab', tabId);
            window.history.pushState({}, '', url);
            if (window.innerWidth <= 1024) document.getElementById('sidebar')?.classList.remove('mobile-open');
          } else {
            window.location.href = tabLink.href;
          }
        }
      });

      // Theme Logic
      (function () {
        const btn = document.getElementById("btnTheme");
        const icon = document.getElementById("themeIcon");
        function isDark() { return document.documentElement.classList.contains("dark"); }
        function sync() { if(icon) icon.className = isDark() ? "fa-solid fa-sun w-5 text-center" : "fa-solid fa-moon w-5 text-center"; }
        sync();
        if(btn) btn.addEventListener("click", () => {
          const next = isDark() ? "light" : "dark";
          document.documentElement.classList.toggle("dark");
          localStorage.setItem("theme", next);
          sync();
        });
      })();

      // ✅ WEATHER LOGIC (Seropédica)
      async function updateWeather() {
        try {
          const res = await fetch('https://api.open-meteo.com/v1/forecast?latitude=-22.7486&longitude=-43.7081&current_weather=true');
          const data = await res.json();
          if (data && data.current_weather) {
            const temp = Math.round(data.current_weather.temperature);
            const code = data.current_weather.weathercode;
            
            const tempEl = document.getElementById('weather-temp');
            const tempMobileEl = document.getElementById('weather-temp-mobile');
            if (tempEl) tempEl.textContent = temp + '°C';
            if (tempMobileEl) tempMobileEl.textContent = temp + '°C';
            
            const iconEl = document.getElementById('weather-icon');
            const boxEl = document.getElementById('weather-icon-box');
            
            if (iconEl && boxEl) {
              // Mapeamento simples de weathercode (WMO)
              if (code === 0) {
                iconEl.className = 'fa-solid fa-sun text-sm';
                boxEl.className = 'w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-500';
              } else if (code <= 3) {
                iconEl.className = 'fa-solid fa-cloud-sun text-sm';
                boxEl.className = 'w-8 h-8 rounded-lg bg-blue-400/10 flex items-center justify-center text-blue-400';
              } else if (code <= 48) {
                iconEl.className = 'fa-solid fa-cloud text-sm';
                boxEl.className = 'w-8 h-8 rounded-lg bg-slate-400/10 flex items-center justify-center text-slate-400';
              } else if (code <= 67) {
                iconEl.className = 'fa-solid fa-cloud-showers-heavy text-sm';
                boxEl.className = 'w-8 h-8 rounded-lg bg-indigo-400/10 flex items-center justify-center text-indigo-400';
              } else {
                iconEl.className = 'fa-solid fa-cloud-bolt text-sm';
                boxEl.className = 'w-8 h-8 rounded-lg bg-red-400/10 flex items-center justify-center text-red-400';
              }
            }
          }
        } catch (e) {
          console.error("Erro ao carregar o clima de Seropédica:", e);
        }
      }

      // Ciclo de vida do clima
      updateWeather();
      setInterval(updateWeather, 900000); // Atualiza a cada 15 minutos

      // ✅ GESTÃO DE NOTIFICAÇÕES (DRAWER E BADGE)
      function toggleNotifications() {
        const drawer = document.getElementById('notification-drawer');
        const overlay = document.getElementById('drawer-overlay');
        if (drawer && overlay) {
          const isOpen = drawer.classList.contains('open');
          if (isOpen) {
            drawer.classList.remove('open');
            overlay.classList.remove('visible');
          } else {
            drawer.classList.add('open');
            overlay.classList.add('visible');
            loadNotifications();
          }
        }
      }

      async function loadNotifications() {
        const list = document.getElementById('notif-list');
        if (!list) return;
        
        list.innerHTML = `
          <div class="text-center py-20">
            <div class="animate-spin inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full mb-4"></div>
            <p class="text-[10px] font-black text-slate-400 uppercase tracking-widest">Carregando...</p>
          </div>
        `;
        
        try {
          const res = await fetch('/api/comunicados/recent');
          const data = await res.json();
          if (data && data.notifications) {
            updateNotifBadge(data.unread_count);
            if (data.notifications.length === 0) {
              list.innerHTML = `
                <div class="text-center py-20">
                  <div class="w-12 h-12 rounded-2xl bg-slate-500/5 flex items-center justify-center text-slate-400 mx-auto mb-4">
                    <i class="fa-solid fa-bell-slash text-lg"></i>
                  </div>
                  <p class="text-xs font-bold text-slate-400">Nenhum comunicado recente</p>
                </div>
              `;
              return;
            }
            
            list.innerHTML = data.notifications.map(n => `
              <div onclick="markAsRead(${n.id}, this)" class="p-4 rounded-2xl border transition-all cursor-pointer relative overflow-hidden group ${
                n.is_read 
                  ? 'bg-slate-500/5 border-slate-900/5 dark:border-white/5 opacity-75 hover:opacity-100' 
                  : 'bg-blue-500/5 border-blue-500/10 hover:bg-blue-500/10'
              }">
                ${!n.is_read ? '<span class="absolute top-4 right-4 w-2 h-2 rounded-full bg-blue-500"></span>' : ''}
                <div class="flex items-center gap-2 mb-1">
                  <span class="text-[9px] font-black px-2 py-0.5 rounded-full ${
                    n.is_read ? 'bg-slate-500/10 text-slate-500' : 'bg-blue-500/10 text-blue-500'
                  } uppercase tracking-wider">${n.sender}</span>
                  <span class="text-[10px] font-bold text-slate-400">${n.created_at}</span>
                </div>
                <h4 class="text-sm font-black text-slate-900 dark:text-white mb-1 group-hover:text-blue-500 transition-colors">${n.title}</h4>
                <p class="text-xs text-slate-500 dark:text-slate-400 whitespace-pre-wrap mt-1 leading-relaxed">${n.message}</p>
              </div>
            `).join('');
          }
        } catch (e) {
          console.error("Erro ao carregar notificações:", e);
          list.innerHTML = `
            <div class="text-center py-20 text-red-500">
              <i class="fa-solid fa-triangle-exclamation text-2xl mb-2"></i>
              <p class="text-xs font-bold">Falha ao carregar notificações</p>
            </div>
          `;
        }
      }

      async function markAsRead(id, element) {
        try {
          const res = await fetch(`/api/comunicados/${id}/read`, { method: 'POST' });
          if (res.ok) {
            element.classList.remove('bg-blue-500/5', 'border-blue-500/10');
            element.classList.add('bg-slate-500/5', 'border-slate-900/5', 'dark:border-white/5', 'opacity-75');
            const dot = element.querySelector('.bg-blue-500');
            if (dot) dot.remove();
            
            // Recarrega badge
            fetchNotifCount();
          }
        } catch (e) {
          console.error("Erro ao marcar como lida:", e);
        }
      }

      function updateNotifBadge(count) {
        const badge = document.getElementById('notif-badge');
        if (badge) {
          if (count > 0) {
            badge.textContent = count;
            badge.classList.remove('hidden');
          } else {
            badge.classList.add('hidden');
          }
        }
      }

      async function fetchNotifCount() {
        try {
          const res = await fetch('/api/comunicados/recent');
          const data = await res.json();
          if (data) {
            updateNotifBadge(data.unread_count);
          }
        } catch (e) {
          console.error("Erro ao buscar contagem de notificações:", e);
        }
      }

      // ✅ AJUDA E MANUAIS CONTEXTUAIS
      function toggleHelp() {
        openModal('modalHelp');
        loadHelpManual();
      }

      async function loadHelpManual() {
        const content = document.getElementById('help-content');
        if (!content) return;
        
        content.innerHTML = `
          <div class="text-center py-10">
            <div class="animate-spin inline-block w-6 h-6 border-2 border-slate-500 border-t-transparent rounded-full mb-4"></div>
            <p class="text-[10px] font-black text-slate-400 uppercase tracking-widest">Carregando manual...</p>
          </div>
        `;
        
        try {
          const res = await fetch('/api/manuais/help');
          const data = await res.json();
          if (data && data.content) {
            content.textContent = data.content;
          }
        } catch (e) {
          console.error("Erro ao carregar manual:", e);
          content.innerHTML = `
            <div class="text-center py-10 text-red-500">
              <i class="fa-solid fa-triangle-exclamation text-2xl mb-2"></i>
              <p class="text-xs font-bold">Falha ao carregar manual</p>
            </div>
          `;
        }
      }

      // Inicializa na carga da página
      window.addEventListener('DOMContentLoaded', () => {
        fetchNotifCount();
        setInterval(fetchNotifCount, 60000); // Atualiza a cada minuto
      });
    