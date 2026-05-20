
let currentTab = 'dashboard';
let currentAtividades = [];
let currentAnotacoes = [];
let currentAnotacaoTab = 'Geral';
let currentRFOs = [];
let currentGenerators = [];
let globalUsers = [];
let selectedTechsEncerramento = [];

async function loadPatios() {
    const res = await fetch('/api/gestao/patios');
    const patios = await res.json();
    const manageList = document.getElementById('list-patios-manage');
    if(manageList) {
        manageList.innerHTML = patios.map(p => `
            <div class="flex justify-between items-center p-3 bg-slate-50 dark:bg-white/5 rounded-xl border border-slate-900/10 dark:border-white/10">
                <span class="text-sm font-bold text-slate-700 dark:text-gray-300">${p.name}</span>
                <button onclick="deletePatio(${p.id})" class="text-red-400 hover:text-red-600"><i class="fa-solid fa-trash-can"></i></button>
            </div>
        `).join('');
    }
    const closingContainer = document.getElementById('patios-closing-container');
    if(closingContainer) {
        closingContainer.innerHTML = patios.map(p => `
            <div class="flex flex-col gap-1 p-3 bg-slate-50/50 dark:bg-white/5 rounded-xl border border-slate-900/10 dark:border-white/10">
                <label class="text-[10px] font-bold text-slate-500 uppercase">${p.name}</label>
                <input type="time" class="patio-closing-input bg-white dark:bg-gray-800 border-none rounded-lg px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-emerald-500/20" 
                       data-id="${p.id}" data-name="${p.name}" onchange="saveEncerramentoDraft()">
            </div>
        `).join('');
    }
}

async function openModalPatios() {
    loadPatios();
    openModal('modal-patios');
}

async function deletePatio(id) {
    if(!confirm("Excluir este pátio?")) return;
    const res = await fetch(`/api/gestao/patios/${id}`, { method: 'DELETE' });
    if(res.ok) loadPatios();
}

document.getElementById('form-patio').onsubmit = async (e) => {
    e.preventDefault();
    const name = e.target.name.value;
    const res = await fetch('/api/gestao/patios', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: name})
    });
    if(res.ok) {
        e.target.reset();
        loadPatios();
    }
};

function saveEncerramentoDraft() {
    const draft = {
        patios: [],
        techs: selectedTechsEncerramento,
        obs: document.getElementById('enc_obs').value
    };
    document.querySelectorAll('.patio-closing-input').forEach(input => {
        draft.patios.push({
            patio_id: input.dataset.id,
            patio_name: input.dataset.name,
            closing_time: input.value
        });
    });
    localStorage.setItem('encerramento_draft', JSON.stringify(draft));
    const status = document.getElementById('draft-status');
    if(status) {
        status.classList.remove('opacity-0');
        setTimeout(() => status.classList.add('opacity-0'), 1500);
    }
}

function loadEncerramentoDraft() {
    const saved = localStorage.getItem('encerramento_draft');
    if(!saved) return;
    try {
        const draft = JSON.parse(saved);
        selectedTechsEncerramento = draft.techs || [];
        document.getElementById('enc_obs').value = draft.obs || "";
        if(draft.patios) {
            draft.patios.forEach(p => {
                const input = document.querySelector(`.patio-closing-input[data-id="${p.patio_id}"]`);
                if(input) input.value = p.closing_time;
            });
        }
        renderSelectedTechs();
    } catch(e) { console.error("Erro ao carregar rascunho:", e); }
}

async function openModalEncerramento() {
    await loadPatios();
    await loadUsers();
    const techSelect = document.getElementById('enc_tech_select');
    if(techSelect && globalUsers) {
        techSelect.innerHTML = '<option value="">Técnico</option>' + 
            globalUsers.map(u => `<option value="${u.id}">${u.username}</option>`).join('');
    }
    selectedTechsEncerramento = [];
    document.getElementById('form-encerramento').reset();
    loadEncerramentoDraft();
    openModal('modal-encerramento');
}

function addTechToEncerramento() {
    const select = document.getElementById('enc_tech_select');
    const time = document.getElementById('enc_tech_time').value;
    if(!select.value || !time) return showToast("Selecione o técnico e a hora.", "warning");
    const username = select.options[select.selectedIndex].text;
    selectedTechsEncerramento.push({ user_id: select.value, username: username, arrival_time: time });
    saveEncerramentoDraft();
    renderSelectedTechs();
}

function renderSelectedTechs() {
    const container = document.getElementById('selected-techs-container');
    container.innerHTML = selectedTechsEncerramento.map((t, idx) => `
        <div class="flex justify-between items-center p-2 bg-emerald-50 dark:bg-emerald-900/10 rounded-lg border border-emerald-100 dark:border-emerald-900/30 animate-premium">
            <span class="text-[10px] font-bold text-emerald-700 dark:text-emerald-400">${t.username} - Chegou às ${t.arrival_time}</span>
            <button type="button" onclick="selectedTechsEncerramento.splice(${idx}, 1); saveEncerramentoDraft(); renderSelectedTechs();" class="text-red-400 text-[10px]"><i class="fa-solid fa-xmark"></i></button>
        </div>
    `).join('');
}

async function submitEncerramento() {
    const patios = [];
    document.querySelectorAll('.patio-closing-input').forEach(input => {
        if(input.value) {
            patios.push({
                patio_id: input.dataset.id,
                patio_name: input.dataset.name,
                closing_time: input.value
            });
        }
    });
    if(patios.length === 0) return showToast("Preencha o horário de pelo menos um pátio.", "warning");
    const data = {
        patios: patios,
        technicians: selectedTechsEncerramento,
        obs: document.getElementById('enc_obs').value
    };
    const res = await fetch('/api/gestao/encerramento', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    if(res.ok) {
        localStorage.removeItem('encerramento_draft');
        closeModal('modal-encerramento');
        loadItems('encerramento');
        showToast("Encerramento salvo com sucesso!", "success");
    }
}

async function deleteEncerramento(id) {
    if(!confirm("Excluir este encerramento?")) return;
    const res = await fetch(`/api/gestao/encerramento/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('encerramento');
}

async function loadUsers() {
    try {
        const res = await fetch('/api/gestao/users');
        const users = await res.json();
        globalUsers = users;
        const select = document.getElementById('task_responsible_select');
        if(select) {
            select.innerHTML = '<option value="">Selecione um técnico</option>' + 
                users.map(u => `<option value="${u.id}">${u.username}</option>`).join('');
        }
    } catch(e) { console.error(e); }
}

function openModalTarefa() {
    const form = document.getElementById('form-tarefa');
    form.reset();
    form.querySelector('[name="id"]').value = "";
    document.getElementById('btn-save-tarefa').innerText = "Salvar Tarefa";
    loadUsers();
    openModal('modal-tarefa');
}


async function editTarefa(id) {
    const res = await fetch('/api/gestao/tarefas');
    const tasks = await res.json();
    const t = tasks.find(x => x.id === id);
    if(!t) return;

    await loadUsers();
    const form = document.getElementById('form-tarefa');
    form.querySelector('[name="id"]').value = t.id;
    form.querySelector('[name="title"]').value = t.title;
    form.querySelector('[name="description"]').value = t.description || "";
    form.querySelector('[name="responsible_id"]').value = t.responsible_id || "";
    form.querySelector('[name="priority"]').value = t.priority;
    form.querySelector('[name="status"]').value = t.status;
    form.querySelector('[name="deadline"]').value = t.deadline || "";
    
    document.getElementById('btn-save-tarefa').innerText = "Atualizar Tarefa";
    openModal('modal-tarefa');
}

async function deleteTarefa(id) {
    if(!confirm("Excluir esta tarefa?")) return;
    const res = await fetch(`/api/gestao/tarefas/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('tarefas');
}

async function updateTarefaStatus(id, newStatus) {
    const res = await fetch(`/api/gestao/tarefas/${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ status: newStatus })
    });
    if(res.ok) loadItems('tarefas');
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
    
    // Atualiza o sidebar (que agora é o único menu)
    document.querySelectorAll('.sidebar-tab-link').forEach(link => {
        if (link.getAttribute('data-tab') === tabId) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    const pane = document.getElementById(`pane-${tabId}`);
    if(pane) pane.classList.remove('hidden');

    // ✅ ATUALIZA O HEADER DINAMICAMENTE
    const tabMeta = {
        'equipes': { label: 'Gerenciamento de Equipes', sub: 'Controle total sobre os times de campo e técnicos.', icon: 'fa-users-gear' },
        'calendario': { label: 'Calendário Operacional', sub: 'Visão geral das atividades e agendamentos.', icon: 'fa-calendar-days' },
        'escalas': { label: 'Escalas de Trabalho', sub: 'Organização de escalas manuais e automáticas.', icon: 'fa-clock-rotate-left' },
        'reunioes': { label: 'Reuniões Matinais', sub: 'Registro e acompanhamento de pautas diárias.', icon: 'fa-handshake' },
        'anotacoes': { label: 'Anotações Gerais', sub: 'Bloco de notas e lembretes para a operação.', icon: 'fa-note-sticky' },
        'atividades': { label: 'Atividades Externas', sub: 'Log de execuções e intervenções técnicas.', icon: 'fa-person-digging' },
        'encerramento': { label: 'Encerramento de Turno', sub: 'Relatórios de fechamento e passagem de bastão.', icon: 'fa-door-closed' },
        'rfo': { label: 'Relatórios de Falha (RFO)', sub: 'Documentação de incidentes e falhas técnicas.', icon: 'fa-file-circle-exclamation' },
        'tarefas': { label: 'Tarefas e Pendências', sub: 'Gestão de plano de ação e prioridades.', icon: 'fa-list-check' },
        'geradores': { label: 'Controle de Geradores', sub: 'Monitoramento de combustível e manutenções.', icon: 'fa-bolt' },
        'rota_exata': { label: 'Auditoria Rota Exata', sub: 'Verificação de trajetos e horários planejados.', icon: 'fa-map-location-dot' },
        'supervisao': { label: 'Supervisão de Campo', sub: 'Auditoria técnica individual e segurança.', icon: 'fa-user-check' },
        'treinamentos': { label: 'Treinamentos', sub: 'Capacitação técnica e registros de curso.', icon: 'fa-graduation-cap' },
        'solicitacoes': { label: 'Solicitações Internas', sub: 'Pedidos de material e ordens administrativas.', icon: 'fa-envelope-open-text' },
        'relatorios': { label: 'Relatórios Gerenciais', sub: 'Exportação de dados e KPIs consolidados.', icon: 'fa-file-pdf' }
    };

    const meta = tabMeta[tabId];
    if(meta) {
        const titleEl = document.getElementById('page-header-title');
        const subEl = document.getElementById('page-header-subtitle');
        const breadEl = document.getElementById('page-header-breadcrumb');
        const iconEl = document.getElementById('page-header-icon');

        if(titleEl) titleEl.innerText = meta.label;
        if(subEl) subEl.innerText = meta.sub;
        if(breadEl) breadEl.innerText = meta.label.split(' ')[0];
        if(iconEl) iconEl.className = `fa-solid ${meta.icon} text-xl`;
    }

    currentTab = tabId;
    loadTabData(tabId);
}

function loadTabData(tabId) {
    if(tabId === 'equipes') loadEquipes();
    if(tabId === 'escalas') { loadEquipes(); loadScaleConfig(); loadItems('escalas'); }
    if(tabId === 'calendario') initCalendar();
    if(tabId === 'reunioes') loadItems('reunioes');
    if(tabId === 'anotacoes') {
        switchAnotacaoTab('Geral');
    }
    if(tabId === 'atividades') loadItems('atividades');
    if(tabId === 'rfo') loadItems('rfo');
    if(tabId === 'encerramento') loadItems('encerramento');
    if(tabId === 'tarefas') {
        loadUsers();
        loadItems('tarefas');
    }
    if(tabId === 'geradores') loadItems('geradores');
    if(tabId === 'rota_exata') loadItems('rota_exata');
    if(tabId === 'supervisao') loadItems('supervisao');
    if(tabId === 'solicitacoes') loadItems('solicitacoes');
    if(tabId === 'treinamentos') loadLMSCourses();
}

async function loadItems(slug) {
    const res = await fetch(`/api/gestao/${slug}${slug === 'escalas' ? '?view=list' : ''}${slug === 'escalas' ? '&' : '?'}t=${Date.now()}`);
    const data = await res.json();
    if(slug === 'atividades') currentAtividades = data;
    if(slug === 'rfo') currentRFOs = data;
    if(slug === 'geradores') currentGenerators = data;
    if(slug === 'rota_exata') rotaExataData = data;
    const container = document.getElementById(`list-${slug}`);
    if(!container) return;

    if(slug === 'encerramento') {
        container.innerHTML = data.map(i => `
            <div class="bg-white/70 dark:bg-white/5 p-6 rounded-3xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-xl transition-all relative overflow-hidden group animate-premium">
                <div class="flex justify-between items-start mb-4">
                    <span class="px-3 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 rounded-full text-[10px] font-bold uppercase">${i.patio_name}</span>
                    <button onclick="deleteEncerramento(${i.id})" class="text-slate-400 hover:text-red-600 transition-colors"><i class="fa-solid fa-trash-can"></i></button>
                </div>
                
                <h4 class="text-sm font-bold text-slate-800 dark:text-white mb-1">Encerramento em ${new Date(i.date + 'T00:00:00').toLocaleDateString()}</h4>
                <p class="text-[10px] text-slate-500 dark:text-gray-400 mb-4 font-bold uppercase tracking-widest">
                    <i class="fa-solid fa-lock"></i> Fechamentos: ${(i.patios || []).map(p => `${p.patio_name} (${p.closing_time})`).join(', ')}
                </p>

                <div class="space-y-2 mb-6">
                    <p class="text-[9px] font-bold text-slate-400 uppercase tracking-widest border-b border-slate-900/5 dark:border-white/5 pb-1">Técnicos Presentes</p>
                    ${i.techs.map(t => `
                        <div class="flex justify-between items-center text-[10px] text-slate-600 dark:text-gray-300">
                            <span class="font-medium">${t.username}</span>
                            <span class="font-bold">Chegou: ${t.arrival_time}</span>
                        </div>
                    `).join('')}
                </div>

                <div class="flex items-center justify-between pt-4 border-t border-slate-900/5 dark:border-white/5">
                    <button onclick="window.open('/api/gestao/encerramento/${i.id}/pdf', '_blank')" class="w-full py-2.5 bg-emerald-50 hover:bg-emerald-100 text-emerald-600 rounded-xl text-[10px] font-bold flex items-center justify-center gap-2 transition-all">
                        <i class="fa-solid fa-file-pdf"></i> Gerar Relatório PDF
                    </button>
                </div>
            </div>
        `).join('');
    } else if(slug === 'tarefas') {
        container.innerHTML = data.map(i => {
            let priorityColor = 'text-slate-400 bg-slate-100';
            if(i.priority === 'Alta') priorityColor = 'text-orange-600 bg-orange-100';
            else if(i.priority === 'Crítica') priorityColor = 'text-red-600 bg-red-100 animate-pulse';
            else if(i.priority === 'Baixa') priorityColor = 'text-blue-600 bg-blue-100';

            let statusColor = 'bg-slate-500';
            if(i.status === 'Em Andamento') statusColor = 'bg-indigo-500';
            else if(i.status === 'Concluída') statusColor = 'bg-emerald-500';

            return `
                <div class="bg-white/70 dark:bg-white/5 p-6 rounded-3xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-xl transition-all relative overflow-hidden group animate-premium">
                    <div class="flex justify-between items-start mb-4">
                        <span class="px-3 py-1 ${priorityColor} rounded-full text-[10px] font-bold uppercase tracking-wider">${i.priority}</span>
                        <div class="flex gap-2">
                            <button onclick="editTarefa(${i.id})" class="text-slate-400 hover:text-indigo-600 transition-colors"><i class="fa-solid fa-pen"></i></button>
                            <button onclick="deleteTarefa(${i.id})" class="text-slate-400 hover:text-red-600 transition-colors"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                    
                    <h4 class="text-lg font-bold text-slate-800 dark:text-white mb-2 ${i.status === 'Concluída' ? 'line-through opacity-50' : ''}">${i.title}</h4>
                    <p class="text-xs text-slate-500 dark:text-gray-400 mb-4 line-clamp-2">${i.description || 'Sem descrição'}</p>
                    
                    <div class="grid grid-cols-2 gap-4 mb-6">
                        <div class="flex flex-col">
                            <span class="text-[10px] font-bold text-slate-400 uppercase">Responsável</span>
                            <span class="text-xs font-bold text-slate-700 dark:text-gray-300">${i.responsible}</span>
                        </div>
                        <div class="flex flex-col items-end">
                            <span class="text-[10px] font-bold text-slate-400 uppercase">Prazo</span>
                            <span class="text-xs font-bold text-slate-700 dark:text-gray-300">${i.deadline ? new Date(i.deadline + 'T00:00:00').toLocaleDateString() : 'N/D'}</span>
                        </div>
                    </div>

                    <div class="flex items-center justify-between pt-4 border-t border-slate-900/5 dark:border-white/5">
                        <div class="flex items-center gap-2">
                            <div class="w-2.5 h-2.5 rounded-full ${statusColor}"></div>
                            <span class="text-[10px] font-bold text-slate-500 uppercase tracking-widest">${i.status}</span>
                        </div>
                        
                        <div class="flex gap-1">
                            ${i.status === 'Pendente' ? `
                                <button onclick="updateTarefaStatus(${i.id}, 'Em Andamento')" class="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-600 rounded-lg text-[10px] font-bold transition-all">Iniciar</button>
                            ` : ''}
                            ${i.status === 'Em Andamento' ? `
                                <button onclick="updateTarefaStatus(${i.id}, 'Concluída')" class="px-3 py-1.5 bg-emerald-50 hover:bg-emerald-100 text-emerald-600 rounded-lg text-[10px] font-bold transition-all">Concluir</button>
                            ` : ''}
                            ${i.status === 'Concluída' ? `
                                <i class="fa-solid fa-circle-check text-emerald-500 text-lg"></i>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    } else if(slug === 'escalas') {
        const resE = await fetch(`/api/gestao/escalas?view=list&t=${Date.now()}`);
        const scales = await resE.json();
        container.innerHTML = scales.map(s => {
            let names = 'Sem equipe';
            if(s.team_ids) {
                const ids = s.team_ids.split(',').map(x => parseInt(x));
                names = globalEquipes.filter(e => ids.includes(e.id)).map(e => e.name).join(' + ');
            }
            return `
            <div class="flex items-center justify-between p-4 bg-white/70 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-xl group transition-all hover:border-purple-500/30">
                <div class="flex flex-1 items-center gap-4">
                    <div class="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center text-purple-600">
                        <i class="fa-solid fa-calendar-check"></i>
                    </div>
                    <div>
                        <div class="text-sm font-bold text-slate-800 dark:text-white">${new Date(s.date + 'T00:00:00').toLocaleDateString()} - ${s.type.toUpperCase()}</div>
                        <div class="text-[10px] text-slate-500 font-bold">${names}</div>
                        <div class="text-[9px] text-slate-400 italic">${s.technician_names || 'Nenhum técnico'}</div>
                    </div>
                </div>
                <div class="flex gap-2">
                    <button onclick="editEscala(${s.id})" class="p-2 text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-500/10 rounded-lg transition-colors"><i class="fa-solid fa-pen"></i></button>
                    <button onclick="deleteEscala(${s.id})" class="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"><i class="fa-solid fa-trash"></i></button>
                </div>
            </div>`;
        }).join('');
    } else if(slug === 'atividades') {
        container.innerHTML = data.map(i => `
            <div class="bg-white/70 dark:bg-white/5 p-6 rounded-3xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-xl transition-all group overflow-hidden relative">
                <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-30 transition-opacity">
                    <i class="fa-solid fa-clipboard-check text-4xl"></i>
                </div>
                <div class="flex justify-between items-start mb-4">
                    <span class="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full text-[10px] font-bold uppercase">${i.type}</span>
                    <span class="text-[10px] text-slate-400 font-bold">${i.date ? new Date(i.date + 'T00:00:00').toLocaleDateString() : '-'} ${i.time || ''}</span>
                </div>
                <h4 class="font-bold text-slate-800 dark:text-white mb-1">${i.client_name || 'Sem nome'}</h4>
                <p class="text-[10px] text-slate-500 font-bold mb-4 uppercase tracking-wider">CÓD: ${i.client_code || '-'}</p>
                
                <div class="space-y-3 mb-4">
                    <div class="flex items-center gap-2">
                        <div class="w-6 h-6 rounded-lg bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center text-blue-500 text-[10px]">
                            <i class="fa-solid fa-user-gear"></i>
                        </div>
                        <span class="text-xs text-slate-600 dark:text-gray-300 font-medium">${i.tech || 'Não informado'}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="w-6 h-6 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 flex items-center justify-center text-emerald-500 text-[10px]">
                            <i class="fa-solid fa-star"></i>
                        </div>
                        <span class="text-xs text-slate-600 dark:text-gray-300 font-medium">${i.quality || 'N/A'}</span>
                    </div>
                </div>

                <div class="p-3 bg-slate-50 dark:bg-white/5 rounded-xl border border-slate-900/5 dark:border-white/5">
                    <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Conclusão</p>
                    <p class="text-xs text-slate-500 dark:text-gray-400 line-clamp-2">${i.conclusion || 'Sem observações'}</p>
                </div>

                <div class="flex justify-between items-center mt-4 pt-4 border-t border-slate-900/5 dark:border-white/5">
                    <button onclick="downloadVistoriaPDF(${i.id})" class="text-[10px] font-bold text-purple-600 hover:text-purple-700 flex items-center gap-1 transition-colors group/btn">
                        <i class="fa-solid fa-file-pdf group-hover/btn:scale-110 transition-transform"></i> PDF
                    </button>
                    <div class="flex gap-2">
                        <button onclick="editAtividade(${i.id})" class="text-blue-500 hover:text-blue-700 p-1" title="Editar"><i class="fa-solid fa-pen"></i></button>
                        <button onclick="deleteAtividade(${i.id})" class="text-red-500 hover:text-red-700 p-1" title="Excluir"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
            </div>
        `).join('');
    } else if(slug === 'reunioes') {
        container.innerHTML = data.map(i => `
            <div class="bg-white/70 dark:bg-white/5 p-5 rounded-2xl border border-slate-900/10 dark:border-white/10 flex flex-col justify-between ${i.status === 'Concluída' ? 'opacity-75' : ''}">
                <div>
                    <div class="flex justify-between items-start mb-3">
                        <div class="flex flex-col gap-1">
                            <span class="px-3 py-1 ${i.status === 'Concluída' ? 'bg-green-100 text-green-700' : 'bg-purple-100 text-purple-600'} rounded-full text-[10px] font-bold uppercase w-fit">${i.status}</span>
                            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">${i.title}</span>
                        </div>
                        <div class="flex gap-2">
                            <button onclick="downloadMeetingPDF(${i.id})" class="text-slate-500 hover:text-purple-600 p-1" title="Gerar PDF"><i class="fa-solid fa-file-pdf"></i></button>
                            <button onclick="editReuniao(${i.id})" class="text-blue-500 hover:text-blue-700 p-1"><i class="fa-solid fa-pen"></i></button>
                            <button onclick="deleteReuniao(${i.id})" class="text-red-500 hover:text-red-700 p-1"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                    <span class="text-xs text-slate-400 font-semibold mb-2 block">${i.date} às ${i.time}</span>
                    <h4 class="font-bold text-slate-800 dark:text-white mb-2 ${i.status === 'Concluída' ? 'line-through' : ''}">${i.subject}</h4>
                    <p class="text-xs text-slate-500 flex items-center gap-2">
                        <i class="fa-solid fa-location-dot"></i> ${i.location || 'Não especificado'}
                    </p>
                </div>
                ${i.status !== 'Concluída' ? `
                    <button onclick="updateStatus('reunioes', ${i.id}, 'Concluída')" class="mt-4 w-full py-2 bg-green-600 hover:bg-green-700 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-green-500/20">
                        Marcar como Realizada
                    </button>
                ` : ''}
            </div>
        `).join('');
    } else if(slug === 'anotacoes') {
        currentAnotacoes = data;
        const filtered = data.filter(i => i.category === currentAnotacaoTab);
        
        if(filtered.length === 0) {
            container.innerHTML = `
                <div class="col-span-full py-20 text-center opacity-30">
                    <i class="fa-solid fa-note-sticky text-4xl mb-3"></i>
                    <p class="text-sm">Nenhuma anotação nesta categoria.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = filtered.map(i => `
            <div class="bg-white/70 dark:bg-white/5 p-6 rounded-3xl border border-slate-900/10 dark:border-white/10 group relative transition-all hover:shadow-xl animate-premium">
                <div class="flex justify-between items-start mb-4">
                    <span class="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full text-[10px] font-bold uppercase tracking-wider">${i.category}</span>
                    <div class="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onclick="editAnotacao(${i.id})" class="w-8 h-8 flex items-center justify-center bg-blue-50 dark:bg-blue-900/30 text-blue-500 rounded-full hover:bg-blue-100"><i class="fa-solid fa-pen text-[10px]"></i></button>
                        <button onclick="deleteAnotacao(${i.id})" class="w-8 h-8 flex items-center justify-center bg-red-50 dark:bg-red-900/30 text-red-500 rounded-full hover:bg-red-100"><i class="fa-solid fa-trash text-[10px]"></i></button>
                    </div>
                </div>
                <h4 class="font-bold text-slate-800 dark:text-white mb-3 text-sm leading-tight">${i.title}</h4>
                <p class="text-xs text-slate-500 dark:text-gray-400 line-clamp-4 mb-4 leading-relaxed">${i.description}</p>
                <div class="flex justify-between items-center text-[10px] text-slate-400 border-t border-slate-900/5 dark:border-white/5 pt-4">
                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-user-circle"></i> ${i.user}</span>
                    <span class="flex items-center gap-1.5"><i class="fa-solid fa-clock"></i> ${new Date(i.date).toLocaleDateString()}</span>
                </div>
            </div>
        `).join('');
    } else if(slug === 'rfo') {
        container.innerHTML = data.map(i => `
            <div class="bg-white/70 dark:bg-white/5 p-6 rounded-3xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-xl transition-all relative overflow-hidden group">
                <div class="absolute top-0 right-0 p-6 opacity-5 group-hover:opacity-10 transition-opacity">
                    <i class="fa-solid fa-triangle-exclamation text-5xl text-red-600"></i>
                </div>
                <div class="flex justify-between items-start mb-4">
                    <div class="flex flex-col gap-1">
                        <span class="px-3 py-1 bg-red-100 dark:bg-red-900/30 text-red-600 rounded-full text-[10px] font-bold uppercase w-fit">${i.status}</span>
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Protocolo: ${i.number}</span>
                    </div>
                    <span class="text-[10px] text-slate-400 font-bold">${new Date(i.date + 'T00:00:00').toLocaleDateString()}</span>
                </div>
                <h4 class="font-bold text-slate-800 dark:text-white mb-2 line-clamp-1">${i.problem_type || 'Falha Operacional'}</h4>
                <div class="space-y-2 mb-4">
                    <p class="text-xs text-slate-500 flex items-center gap-2"><i class="fa-solid fa-location-dot w-3"></i> ${i.city || 'Local não informado'}</p>
                    <p class="text-xs text-slate-500 flex items-center gap-2"><i class="fa-solid fa-user-shield w-3"></i> ${i.tech || 'Sem técnico'}</p>
                </div>
                <div class="flex justify-between items-center pt-4 border-t border-slate-900/5 dark:border-white/5">
                    <button onclick="downloadRFOPDF(${i.id})" class="text-[10px] font-bold text-red-600 hover:text-red-700 flex items-center gap-1">
                        <i class="fa-solid fa-file-pdf"></i> GERAR RFO PDF
                    </button>
                    <div class="flex gap-2">
                        <button onclick="editRFO(${i.id})" class="text-blue-500 hover:text-blue-700 p-1" title="Editar"><i class="fa-solid fa-pen"></i></button>
                        <button onclick="deleteRFO(${i.id})" class="text-red-500 hover:text-red-700 p-1" title="Excluir"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
            </div>
        `).join('');
    } else if(slug === 'geradores') {
        container.innerHTML = data.map(i => {
            const perc = Math.min(100, Math.round((i.current_qty / i.capacity_total) * 100));
            let colorClass = 'bg-orange-500';
            if(perc < 25) colorClass = 'bg-red-500';
            else if(perc < 50) colorClass = 'bg-amber-500';
            else colorClass = 'bg-emerald-500';
            
            return `
                <div class="bg-white/70 dark:bg-white/5 rounded-3xl border border-slate-900/10 dark:border-white/10 p-6 shadow-sm hover:shadow-xl transition-all group overflow-hidden relative animate-premium">
                    <div class="flex justify-between items-start mb-6">
                        <div>
                            <h3 class="font-bold text-slate-800 dark:text-white text-lg">${i.name}</h3>
                            <p class="text-xs text-slate-500 flex items-center gap-1"><i class="fa-solid fa-location-dot"></i> ${i.location}</p>
                        </div>
                        <span class="px-3 py-1 bg-slate-100 dark:bg-white/10 text-slate-500 rounded-full text-[10px] font-bold uppercase">${i.fuel_type}</span>
                    </div>
                    
                    <div class="flex gap-6 items-center mb-6">
                        <div class="w-24 h-40 fuel-tank flex-shrink-0">
                            <div class="fuel-level ${colorClass}" style="height: ${perc}%">
                                <div class="fuel-wave"></div>
                            </div>
                            <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
                                <span class="text-xl font-black ${perc > 50 ? 'text-white/40' : 'text-slate-400'}">${perc}%</span>
                            </div>
                        </div>
                        <div class="flex-1 space-y-4">
                            <div class="p-3 bg-slate-50 dark:bg-white/5 rounded-2xl border border-slate-900/5 dark:border-white/5">
                                <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Status do Tanque</p>
                                <div class="flex justify-between items-end">
                                    <span class="text-2xl font-black text-slate-700 dark:text-white">${i.current_qty}<small class="text-xs ml-1 font-bold text-slate-400">L</small></span>
                                    <span class="text-[10px] font-bold text-slate-400">TOTAL: ${i.capacity_total}L</span>
                                </div>
                            </div>
                            <div class="p-3 bg-blue-50/50 dark:bg-blue-900/10 rounded-2xl border border-blue-100 dark:border-blue-900/30">
                                <p class="text-[10px] font-bold text-blue-600 dark:text-blue-400 uppercase mb-1">Galões Reserva</p>
                                <div class="flex items-center gap-2">
                                    <i class="fa-solid fa-fill-drip text-blue-400"></i>
                                    <span class="font-bold text-blue-700 dark:text-blue-300">${i.reserve_cans} <small class="text-[10px]">Unid.</small></span>
                                    <span class="mx-2 text-blue-200">|</span>
                                    <span class="font-bold text-blue-700 dark:text-blue-300">${i.reserve_liters}<small class="text-[10px]">L</small></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="grid grid-cols-2 gap-3 pt-4 border-t border-slate-900/5 dark:border-white/5">
                        <button onclick="openAbastecer(${i.id})" class="py-2.5 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-xs font-bold shadow-lg shadow-orange-500/20 flex items-center justify-center gap-2 transition-all active:scale-95">
                            <i class="fa-solid fa-gas-pump"></i> Abastecer
                        </button>
                        <div class="flex gap-2">
                            <button onclick="editGerador(${i.id})" class="flex-1 py-2.5 border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-50 dark:hover:bg-white/5 rounded-xl text-xs font-bold transition-all"><i class="fa-solid fa-pen"></i></button>
                            <button onclick="deleteGerador(${i.id})" class="flex-1 py-2.5 border border-red-100 text-red-400 hover:bg-red-50 rounded-xl text-xs font-bold transition-all"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    } else if(slug === 'rota_exata') {
        rotaExataData = data;
        container.innerHTML = data.map(i => `
            <div class="card-premium p-6 group relative animate-premium">
                <div class="flex justify-between items-start mb-4">
                    <div class="flex flex-col">
                        <span class="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full text-[10px] font-bold uppercase w-fit mb-1">Rota Exata</span>
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">${new Date(i.date_created).toLocaleDateString()}</span>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="downloadRotaPDF(${i.id})" class="text-slate-400 hover:text-purple-600 p-1" title="Gerar PDF"><i class="fa-solid fa-file-pdf"></i></button>
                        <button onclick="editRota(${i.id})" class="text-blue-500 hover:text-blue-700 p-1"><i class="fa-solid fa-pen"></i></button>
                        <button onclick="deleteRota(${i.id})" class="text-red-500 hover:text-red-700 p-1"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
                <h4 class="font-bold text-slate-800 dark:text-white mb-2">
                    <i class="fa-solid fa-route text-purple-500 mr-2"></i> ${(i.techs_data || []).length} Técnico(s)
                </h4>
                <div class="mb-4">
                    <p class="text-[10px] text-slate-400 uppercase font-black tracking-widest mb-2">Participantes:</p>
                    <div class="flex flex-wrap gap-1">
                        ${(i.techs_data || []).map(t => `<span class="px-2 py-0.5 bg-slate-100 dark:bg-white/5 rounded text-[9px] font-bold text-slate-600 dark:text-gray-400">${t.tech_name || 'N/A'}</span>`).join('')}
                    </div>
                </div>
                <div class="space-y-1 mb-3">
                    <p class="text-[10px] text-slate-500 font-bold uppercase tracking-wider"><i class="fa-solid fa-user-shield mr-1"></i> Sup: ${i.supervisor || 'N/A'}</p>
                    <p class="text-[10px] text-slate-500"><i class="fa-solid fa-map mr-1"></i> ${(i.techs_data && i.techs_data[0]?.planned_route) || 'N/A'}</p>
                </div>
                <div class="pt-2 border-t border-slate-900/5 dark:border-white/5">
                    <p class="text-[10px] text-slate-400 italic line-clamp-1">ID do Registro: #${String(i.id).padStart(4, '0')}</p>
                </div>
            </div>
        `).join('');
    } else if(slug === 'supervisao') {
        supervisaoData = data;
        container.innerHTML = data.map(i => `
            <div class="card-premium p-6 group relative animate-premium">
                <div class="flex justify-between items-start mb-4">
                    <div class="flex flex-col">
                        <span class="px-3 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 rounded-full text-[10px] font-bold uppercase w-fit mb-1">Supervisão Campo</span>
                        <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">${(i.techs_data && i.techs_data[0]?.supervision_time) || ''}</span>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="downloadSupervisaoPDF(${i.id})" class="text-slate-400 hover:text-emerald-600 p-1" title="Gerar PDF Único"><i class="fa-solid fa-file-pdf"></i></button>
                        <button onclick="editSupervisao(${i.id})" class="text-blue-500 hover:text-blue-700 p-1"><i class="fa-solid fa-pen"></i></button>
                        <button onclick="deleteSupervisao(${i.id})" class="text-red-500 hover:text-red-700 p-1"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
                <h4 class="font-bold text-slate-800 dark:text-white mb-1">
                    <i class="fa-solid fa-users-viewfinder text-emerald-500 mr-2"></i> ${(i.techs_data || []).length} Técnico(s)
                </h4>
                <div class="mb-4">
                    <p class="text-[10px] text-slate-400 uppercase font-black tracking-widest mb-2">Participantes:</p>
                    <div class="flex flex-wrap gap-1">
                        ${(i.techs_data || []).map(t => `<span class="px-2 py-0.5 bg-slate-100 dark:bg-white/5 rounded text-[9px] font-bold text-slate-600 dark:text-gray-400">${t.tech_name || 'N/A'}</span>`).join('')}
                    </div>
                </div>
                <div class="space-y-1 mb-3">
                    <p class="text-[10px] text-slate-500 font-bold uppercase tracking-wider"><i class="fa-solid fa-location-dot mr-1"></i> ${(i.techs_data && i.techs_data[0]?.location) || 'N/A'}</p>
                    <p class="text-[10px] text-slate-500"><i class="fa-solid fa-person-digging mr-1"></i> ${(i.techs_data && i.techs_data[0]?.activity) || 'N/A'}</p>
                </div>
                <div class="pt-2 border-t border-slate-900/5 dark:border-white/5">
                    <p class="text-[10px] text-slate-400 italic line-clamp-2">"${(i.techs_data && i.techs_data[0]?.conclusion) || ''}"</p>
                </div>
            </div>
        `).join('');
    } else {
        container.innerHTML = `<p class="text-slate-400 text-sm italic">Dados carregados: ${data.length} itens.</p>`;
    }
}

// Geolocalização e RFO
async function getRFOPlacement() {
    if (!navigator.geolocation) return showToast("GPS não suportado.", "error");
    
    // Feedback visual de carregamento
    const btn = event.target;
    const originalText = btn.innerText;
    btn.innerText = "Obtendo GPS...";
    btn.disabled = true;

    navigator.geolocation.getCurrentPosition(async (pos) => {
        const lat = pos.coords.latitude;
        const lng = pos.coords.longitude;
        document.querySelector('#form-rfo [name="lat"]').value = lat.toFixed(6);
        document.querySelector('#form-rfo [name="lng"]').value = lng.toFixed(6);
        
        try {
            const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`);
            const data = await res.json();
            if (data.address) {
                document.querySelector('#form-rfo [name="city"]').value = data.address.city || data.address.town || data.address.village || "";
                document.querySelector('#form-rfo [name="neighborhood"]').value = data.address.suburb || data.address.neighbourhood || "";
            }
        } catch (e) { 
            console.error("Erro no reverse geocoding:", e); 
        } finally {
            btn.innerText = originalText;
            btn.disabled = false;
        }
    }, (err) => {
        showToast("Erro ao obter localização: " + err.message, "error");
        btn.innerText = originalText;
        btn.disabled = false;
    }, { enableHighAccuracy: true });
}

function previewPhotos(input, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = "";
    if (input.files) {
        Array.from(input.files).forEach(file => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const div = document.createElement('div');
                div.className = "aspect-square rounded-xl overflow-hidden border border-slate-200 dark:border-white/10 relative shadow-sm";
                div.innerHTML = `<img src="${e.target.result}" class="w-full h-full object-cover">`;
                container.appendChild(div);
            };
            reader.readAsDataURL(file);
        });
    }
}

function openModalRFO() {
    const form = document.getElementById('form-rfo');
    form.reset();
    document.getElementById('rfo-photo-preview').innerHTML = "";
    
    const submitBtn = document.querySelector('#modal-rfo button[onclick^="submitRFO"], #modal-rfo button[onclick^="saveEditRFO"]');
    submitBtn.onclick = submitRFO;
    submitBtn.innerHTML = '<i class="fa-solid fa-file-export"></i> Salvar e Gerar Relatório';
    
    openModal('modal-rfo');
}

async function submitRFO() {
    const form = document.getElementById('form-rfo');
    const formData = new FormData(form);
    
    // Feedback visual
    const btn = document.querySelector('#modal-rfo button[onclick^="submitRFO"]');
    if(!btn) return;
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Salvando...';
    btn.disabled = true;

    try {
        const res = await fetch('/api/gestao/rfo', {
            method: 'POST',
            body: formData
        });
        if (res.ok) {
            closeModal('modal-rfo');
            loadItems('rfo');
            form.reset();
            document.getElementById('rfo-photo-preview').innerHTML = "";
        } else {
            const errData = await res.json();
            alert("Erro ao salvar RFO: " + (errData.error || "Verifique os dados e tente novamente."));
        }
    } catch (e) {
        console.error(e);
        alert("Erro de conexão ao salvar RFO.");
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

function editRFO(id) {
    const item = currentRFOs.find(r => r.id === id);
    if(!item) return;
    
    const form = document.getElementById('form-rfo');
    form.querySelector('[name="protocol"]').value = item.number || '';
    form.querySelector('[name="problem_type"]').value = item.problem_type || '';
    form.querySelector('[name="root_cause"]').value = item.root_cause || '';
    form.querySelector('[name="solution_actions"]').value = item.action || '';
    form.querySelector('[name="maintenance_start"]').value = item.start_time || '';
    form.querySelector('[name="resolution_time"]').value = item.end_time || '';
    form.querySelector('[name="city"]').value = item.city || '';
    form.querySelector('[name="neighborhood"]').value = item.neighborhood || '';
    form.querySelector('[name="lat"]').value = item.lat || '';
    form.querySelector('[name="lng"]').value = item.lng || '';
    form.querySelector('[name="tech_responsible"]').value = item.tech || '';
    form.querySelector('[name="observations"]').value = item.observations || '';
    
    const submitBtn = document.querySelector('#modal-rfo button[onclick^="submitRFO"], #modal-rfo button[onclick^="saveEditRFO"]');
    submitBtn.onclick = () => saveEditRFO(id);
    submitBtn.innerHTML = '<i class="fa-solid fa-save"></i> Salvar Alterações';
    
    openModal('modal-rfo');
}

async function saveEditRFO(id) {
    const form = document.getElementById('form-rfo');
    const data = {};
    new FormData(form).forEach((value, key) => {
        if(key !== 'photos[]') data[key] = value;
    });
    
    try {
        const res = await fetch(`/api/gestao/rfo/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if (res.ok) {
            closeModal('modal-rfo');
            loadItems('rfo');
        }
    } catch(e) { console.error(e); }
}

async function deleteRFO(id) {
    if(!confirm("Deseja realmente excluir este RFO?")) return;
    try {
        const res = await fetch(`/api/gestao/rfo/${id}`, { method: 'DELETE' });
        if(res.ok) loadItems('rfo');
    } catch(e) { console.error(e); }
}

async function submitGerador() {
    const form = document.getElementById('form-gerador');
    form.requestSubmit();
}

function openAbastecer(id) {
    const item = currentGenerators.find(g => g.id === id);
    if(!item) return;
    const form = document.getElementById('form-abastecer');
    form.querySelector('[name="id"]').value = id;
    form.querySelector('[name="current_qty"]').value = item.current_qty;
    form.querySelector('[name="reserve_cans"]').value = item.reserve_cans;
    form.querySelector('[name="reserve_liters"]').value = item.reserve_liters;
    openModal('modal-abastecer');
}

document.getElementById('form-abastecer').onsubmit = async (e) => {
    e.preventDefault();
    const data = {};
    new FormData(e.target).forEach((value, key) => data[key] = value);
    const id = data.id;
    
    try {
        const res = await fetch(`/api/gestao/geradores/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if(res.ok) {
            closeModal('modal-abastecer');
            loadItems('geradores');
        }
    } catch(e) { console.error(e); }
};

async function deleteGerador(id) {
    if(!confirm("Excluir este gerador?")) return;
    const res = await fetch(`/api/gestao/geradores/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('geradores');
}

async function editGerador(id) {
    const item = currentGenerators.find(g => g.id === id);
    if(!item) return;
    const form = document.getElementById('form-gerador');
    form.querySelector('[name="name"]').value = item.name;
    form.querySelector('[name="location"]').value = item.location;
    form.querySelector('[name="capacity_total"]').value = item.capacity_total;
    form.querySelector('[name="current_qty"]').value = item.current_qty;
    form.querySelector('[name="fuel_type"]').value = item.fuel_type;
    form.querySelector('[name="reserve_cans"]').value = item.reserve_cans;
    form.querySelector('[name="reserve_liters"]').value = item.reserve_liters;
    
    const btn = document.querySelector('#modal-gerador button[onclick="submitGerador()"]');
    btn.onclick = () => saveEditGerador(id);
    btn.innerText = "Salvar Alterações";
    
    openModal('modal-gerador');
}

async function saveEditGerador(id) {
    const form = document.getElementById('form-gerador');
    const data = {};
    new FormData(form).forEach((value, key) => data[key] = value);
    
    const res = await fetch(`/api/gestao/geradores/${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    if(res.ok) {
        closeModal('modal-gerador');
        loadItems('geradores');
    }
}

// --- EQUIPES ---

function openModalEquipe() {
    const form = document.getElementById('form-equipe');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    openModal('modal-equipe');
}

async function editEquipe(id) {
    const res = await fetch('/api/gestao/equipes');
    const equipes = await res.json();
    const e = equipes.find(x => x.id === id);
    if(!e) return;

    const form = document.getElementById('form-equipe');
    form.querySelector('[name="id"]').value = e.id;
    form.querySelector('[name="name"]').value = e.name;
    form.querySelector('[name="color"]').value = e.color;
    form.querySelector('[name="obs"]').value = e.obs || '';
    
    // Check members
    const memberIds = e.members.map(m => m.id);
    form.querySelectorAll('input[name="members"]').forEach(i => {
        i.checked = memberIds.includes(parseInt(i.value));
    });

    openModal('modal-equipe');
}

async function deleteEquipe(id) {
    if(!confirm("Tem certeza que deseja excluir esta equipe?")) return;
    const res = await fetch(`/api/gestao/equipes/${id}`, { method: 'DELETE' });
    if(res.ok) {
        loadEquipes();
    } else {
        showToast("Erro ao excluir equipe.", "error");
    }
}

let globalEquipes = [];
let techToTeamMap = {};

async function loadEquipes() {
    const res = await fetch('/api/gestao/equipes');
    globalEquipes = await res.json();
    
    // Atualiza mapeamento de técnicos
    techToTeamMap = {};
    globalEquipes.forEach(eq => {
        eq.members.forEach(m => {
            if(!techToTeamMap[m.id]) techToTeamMap[m.id] = [];
            techToTeamMap[m.id].push({id: eq.id, name: eq.name});
        });
    });

    // 1. Atualiza lista principal de equipes (Aba Equipes)
    const container = document.getElementById('list-equipes');
    if(container) {
        container.innerHTML = globalEquipes.map(e => `
            <div class="bg-white/70 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-2xl p-5 shadow-sm group hover:shadow-md transition-all relative overflow-hidden">
                <div class="absolute top-0 left-0 w-1.5 h-full" style="background-color: ${e.color}"></div>
                <div class="flex justify-between items-start mb-4">
                    <div class="flex items-center gap-3">
                        <div class="w-3 h-3 rounded-full" style="background-color: ${e.color}"></div>
                        <h3 class="font-bold text-slate-800 dark:text-white">${e.name}</h3>
                    </div>
                    <div class="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onclick="editEquipe(${e.id})" class="text-blue-500 hover:text-blue-700"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button onclick="deleteEquipe(${e.id})" class="text-red-500 hover:text-red-700"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
                <div class="space-y-2">
                    <p class="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Membros (${e.members.length})</p>
                    <div class="flex flex-wrap gap-1">
                        ${e.members.map(m => `<span class="px-2 py-0.5 bg-slate-100 dark:bg-white/5 rounded-full text-[10px] text-slate-600 dark:text-gray-300 font-bold">${m.username}</span>`).join('')}
                    </div>
                </div>
            </div>
        `).join('');
    }

    // 2. Atualiza lista de rotatividade (Aba Escalas)
    const rotList = document.getElementById('rotation-teams-list');
    if(rotList) {
        rotList.innerHTML = globalEquipes.map(e => `
            <label class="flex flex-col items-center gap-3 p-4 bg-white/50 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-2xl cursor-pointer hover:bg-purple-50 dark:hover:bg-purple-900/10 transition-all group">
                <input type="checkbox" class="hidden peer" onchange="toggleRotationTeam(${e.id}, this)">
                <div class="w-10 h-10 rounded-2xl bg-slate-100 dark:bg-white/5 flex items-center justify-center text-xs font-black text-slate-400 peer-checked:bg-purple-600 peer-checked:text-white shadow-sm transition-all">
                    <i class="fa-solid fa-check hidden peer-checked:block"></i>
                    <span class="block peer-checked:hidden">${e.id}</span>
                </div>
                <span class="text-[10px] font-black text-slate-500 dark:text-gray-400 text-center uppercase tracking-widest group-hover:text-purple-600 transition-colors">${e.name}</span>
            </label>
        `).join('');
    }

    // 3. Atualiza selects de equipe nos modais
    const teamSelects = document.querySelectorAll('select[name="team_id"]');
    teamSelects.forEach(s => {
        const currentVal = s.value;
        s.innerHTML = '<option value="">Nenhuma (Escala por Técnico)</option>' + 
            globalEquipes.map(e => `<option value="${e.id}">${e.name}</option>`).join('');
        s.value = currentVal;
    });
}

function toggleRotationTeam(id, el) {
    let current = document.getElementById('scale_rotation_order').value.split(',').filter(x => x);
    if(el.checked) {
        if(!current.includes(id.toString())) current.push(id);
    } else {
        current = current.filter(x => x != id);
    }
    document.getElementById('scale_rotation_order').value = current.join(',');
}

function updateEscalaTeams() {
    const checked = Array.from(document.querySelectorAll('#escala-users-list input:checked'));
    const teamIds = new Set();
    const teamNames = new Set();

    checked.forEach(cb => {
        const teams = techToTeamMap[cb.value] || [];
        teams.forEach(t => {
            teamIds.add(t.id);
            teamNames.add(t.name);
        });
    });

    const display = document.getElementById('escala-teams-display');
    const hidden = document.getElementById('escala-team-ids');

    if(teamNames.size > 0) {
        display.innerHTML = Array.from(teamNames).map(name => `<span class="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded text-[10px] font-bold">${name}</span>`).join('');
        hidden.value = Array.from(teamIds).join(',');
    } else {
        display.innerHTML = 'Nenhuma equipe selecionada';
        hidden.value = '';
    }
}

function switchAnotacaoTab(tab) {
    currentAnotacaoTab = tab;
    document.querySelectorAll('.anot-tab-btn').forEach(btn => {
        btn.classList.remove('bg-purple-600', 'text-white', 'shadow-lg', 'shadow-purple-500/20');
        btn.classList.add('bg-slate-100', 'dark:bg-white/5', 'text-slate-500');
    });
    const active = document.getElementById(`btn-anot-${tab}`);
    if(active) {
        active.classList.remove('bg-slate-100', 'dark:bg-white/5', 'text-slate-500');
        active.classList.add('bg-purple-600', 'text-white', 'shadow-lg', 'shadow-purple-500/20');
    }
    loadItems('anotacoes');
}

function toggleAnotDate(show) {
    const container = document.getElementById('anot_date_container');
    if (show) {
        container.classList.remove('hidden');
    } else {
        container.classList.add('hidden');
        document.querySelector('#form-anotacao [name="event_date"]').value = '';
    }
}

function openModalAnotacao() {
    const form = document.getElementById('form-anotacao');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    toggleAnotDate(false);
    openModal('modal-anotacao');
}

async function editAnotacao(id) {
    const res = await fetch('/api/gestao/anotacoes');
    const items = await res.json();
    const item = items.find(x => x.id === id);
    if(!item) return;

    const form = document.getElementById('form-anotacao');
    form.querySelector('[name="id"]').value = item.id;
    form.querySelector('[name="title"]').value = item.title;
    form.querySelector('[name="category"]').value = item.category;
    form.querySelector('[name="description"]').value = item.description;
    
    if (item.event_date) {
        form.querySelector('[name="event_date"]').value = item.event_date;
        document.getElementById('anot_has_date').checked = true;
        toggleAnotDate(true);
    } else {
        document.getElementById('anot_has_date').checked = false;
        toggleAnotDate(false);
    }
    
    openModal('modal-anotacao');
}

async function deleteAnotacao(id) {
    if(!confirm("Deseja excluir esta anotação?")) return;
    const res = await fetch(`/api/gestao/anotacoes/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('anotacoes');
}

function openModalReuniao() {
    const form = document.getElementById('form-reuniao');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    openModal('modal-reuniao');
}

async function editReuniao(id) {
    const res = await fetch('/api/gestao/reunioes');
    const items = await res.json();
    const item = items.find(x => x.id === id);
    if(!item) return;

    const form = document.getElementById('form-reuniao');
    form.querySelector('[name="id"]').value = item.id;
    form.querySelector('[name="title"]').value = item.title;
    form.querySelector('[name="subject"]').value = item.subject;
    form.querySelector('[name="date"]').value = item.date;
    form.querySelector('[name="time"]').value = item.time;
    form.querySelector('[name="location"]').value = item.location || '';
    form.querySelector('[name="responsible"]').value = item.responsible || '';
    form.querySelector('[name="objective"]').value = item.objective || '';
    form.querySelector('[name="summary"]').value = item.summary || '';
    form.querySelector('[name="actions"]').value = item.actions || '';
    
    const techIds = item.technician_ids ? item.technician_ids.split(',') : [];
    form.querySelectorAll('#reuniao-users-list input[type="checkbox"]').forEach(cb => {
        cb.checked = techIds.includes(cb.value.toString());
    });
    
    openModal('modal-reuniao');
}

async function deleteReuniao(id) {
    if(!confirm("Deseja excluir esta reunião?")) return;
    const res = await fetch(`/api/gestao/reunioes/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('reunioes');
}

function openModalEscala() {
    const form = document.getElementById('form-escala');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    document.getElementById('escala-teams-display').innerHTML = 'Nenhuma equipe selecionada';
    document.getElementById('escala-team-ids').value = '';
    openModal('modal-escala');
}

async function editEscala(id) {
    // Busca os dados mais recentes
    const res = await fetch(`/api/gestao/escalas?view=list&t=${Date.now()}`);
    if(!res.ok) return alert("Erro ao carregar dados da escala.");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return alert("Escala não encontrada.");

    const form = document.getElementById('form-escala');
    form.reset(); // Limpa estado anterior
    
    form.querySelector('[name="id"]').value = item.id;
    form.querySelector('[name="type"]').value = item.type;
    form.querySelector('[name="date"]').value = item.date;
    form.querySelector('[name="obs"]').value = item.obs || '';
    
    // Check technicians
    const techIds = item.technician_ids ? item.technician_ids.split(',').map(x => x.trim()) : [];
    form.querySelectorAll('#escala-users-list input[type="checkbox"]').forEach(cb => {
        cb.checked = techIds.includes(cb.value.toString());
    });
    
    updateEscalaTeams();
    openModal('modal-escala');
}

async function deleteEscala(id) {
    if(!confirm("Deseja excluir esta escala manual?")) return;
    const res = await fetch(`/api/gestao/escalas/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('escalas');
}

// --- ENVIO GENÉRICO PARA JSON ---
async function handleJsonSubmit(formId, apiPath, tabToReload) {
    document.getElementById(formId).onsubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = {};
        formData.forEach((value, key) => {
            if (!data[key]) {
                data[key] = value;
            } else {
                if (!Array.isArray(data[key])) {
                    data[key] = [data[key]];
                }
                data[key].push(value);
            }
        });
        
        // Trata membros da equipe se o formulário for de equipe
        if(formId === 'form-equipe') {
            data.member_ids = Array.from(e.target.querySelectorAll('input[name="members"]:checked')).map(i => i.value);
        }
        if(formId === 'form-reuniao') {
            data.technician_ids = Array.from(e.target.querySelectorAll('input[name="technician_ids"]:checked')).map(i => i.value);
        }

        const method = data.id ? 'PUT' : 'POST';
        const url = data.id ? `${apiPath}/${data.id}` : apiPath;

        const res = await fetch(url, {
            method: method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });

        if(res.ok) {
            closeModal(formId.replace('form-', 'modal-'));
            if(tabToReload === 'equipes') loadEquipes();
            loadItems(tabToReload);
            if(calendar) calendar.refetchEvents();
            e.target.reset();
            showToast("Operação concluída com sucesso!", "success");
        } else {
            const err = await res.json();
            showToast("Erro: " + (err.error || "Erro desconhecido ao salvar"), "error");
        }
    };
}

// --- ENVIO PARA MULTIPART (ATIVIDADES / RFO COM FOTOS) ---
async function handleMultipartSubmit(formId, apiPath, tabToReload) {
    document.getElementById(formId).onsubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        const res = await fetch(apiPath, {
            method: 'POST',
            body: formData
        });

        if(res.ok) {
            closeModal(formId.replace('form-', 'modal-'));
            loadItems(tabToReload);
            e.target.reset();
            showToast("Registro enviado com sucesso!", "success");
        } else {
            showToast("Erro ao enviar registro (verifique as fotos).", "error");
        }
    };
}

// Inicializa os handlers
handleJsonSubmit('form-equipe', '/api/gestao/equipes', 'equipes');
handleJsonSubmit('form-escala', '/api/gestao/escalas', 'escalas');
handleJsonSubmit('form-reuniao', '/api/gestao/reunioes', 'reunioes');
handleJsonSubmit('form-anotacao', '/api/gestao/anotacoes', 'anotacoes');
handleMultipartSubmit('form-atividade', '/api/gestao/atividades', 'atividades');
handleMultipartSubmit('form-rfo', '/api/gestao/rfo', 'rfo');
handleJsonSubmit('form-reuniao', '/api/gestao/reunioes', 'reunioes');
handleJsonSubmit('form-tarefa', '/api/gestao/tarefas', 'tarefas');
handleJsonSubmit('form-gerador', '/api/gestao/geradores', 'geradores');
handleJsonSubmit('form-solicitacao', '/api/gestao/solicitacoes', 'solicitacoes');


// Configuração de Escala
document.getElementById('form-config-escala').onsubmit = async (e) => {
    e.preventDefault();
    const data = {
        scale_start_date: document.getElementById('scale_start_date').value,
        scale_rotation_order: document.getElementById('scale_rotation_order').value
    };
    const res = await fetch('/api/gestao/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    if(res.ok) {
        showToast("Configuração salva!", "success");
        if(calendar) calendar.refetchEvents();
    }
};
// --- ESCALAS & CONFIG ---

async function loadScaleConfig() {
    const res = await fetch('/api/gestao/config');
    const data = await res.json();
    document.getElementById('scale_start_date').value = data.scale_start_date || '';
    document.getElementById('scale_rotation_order').value = data.scale_rotation_order || '';
}

// --- CALENDÁRIO ---
let calendar = null;
function initCalendar() {
    if(calendar) return;
    const calendarEl = document.getElementById('calendar');
    calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        locale: 'pt-br',
        firstDay: 0,
        buttonText: {
            today: 'Hoje',
            month: 'Mês',
            week: 'Semana',
            day: 'Dia',
            list: 'Lista'
        },
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek'
        },
        events: '/api/gestao/escalas',
        dayMaxEvents: true,
        height: 'auto',
        eventClick: function(info) {
            if(info.event.id && info.event.id.startsWith('m_')) {
                editEscala(info.event.id.replace('m_', ''));
            } else {
                showToast("Evento: " + info.event.title, "info");
            }
        },
        eventDidMount: function(info) {
            // Adiciona efeitos premium nos eventos
            info.el.classList.add('rounded-lg', 'border-none', 'px-2', 'py-0.5', 'text-[10px]', 'font-bold', 'shadow-sm');
        }
    });
    calendar.render();
}

async function updateStatus(slug, id, status) {
    const res = await fetch(`/api/gestao/${slug}/${id}/status`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: status})
    });
    if(res.ok) {
        loadItems(slug);
    } else {
        alert("Erro ao atualizar status.");
    }
}

function openModal(id) {
    document.getElementById(id).classList.remove('hidden');
    document.getElementById(id).classList.add('flex');
}
function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
    document.getElementById(id).classList.remove('flex');
}

// --- VISTORIAS (DINÂMICO) ---
function openModalVistoria() {
    document.getElementById('vistoria-blocks').innerHTML = '';
    addVistoriaBlock();
    
    const submitBtn = document.getElementById('btn-save-vistoria');
    submitBtn.onclick = submitVistorias;
    submitBtn.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Finalizar e Salvar Registros';
    
    document.querySelector('#modal-vistoria button[onclick="addVistoriaBlock()"]').classList.remove('hidden');
    openModal('modal-vistoria');
}

function addVistoriaBlock() {
    const container = document.getElementById('vistoria-blocks');
    const block = document.createElement('div');
    block.className = 'bg-slate-50 dark:bg-white/5 p-6 rounded-2xl border border-slate-900/10 dark:border-white/10 relative animate-premium';
    block.innerHTML = `
        <button type="button" onclick="this.parentElement.remove()" class="btn-remove-block absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full text-slate-400 hover:bg-red-50 hover:text-red-500 transition-all">
            <i class="fa-solid fa-trash"></i>
        </button>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Técnico Responsável</label>
                <input type="text" name="tech_responsible" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Cliente</label>
                <input type="text" name="client_name" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Código Cliente</label>
                <input type="text" name="client_code" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Atividade Realizada</label>
                <input type="text" name="type" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none" placeholder="Ex: Fusão de Fibra">
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Horário da Visita</label>
                <input type="time" name="time" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Qualidade do Serviço</label>
                <select name="quality_rating" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white outline-none">
                    <option value="Excelente">Excelente</option>
                    <option value="Bom">Bom</option>
                    <option value="Regular">Regular</option>
                    <option value="Ruim">Ruim</option>
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Validação Encerramento O.S</label>
                <select name="os_closure" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white outline-none">
                    <option value="Sim">Sim</option>
                    <option value="Não">Não</option>
                </select>
            </div>
        </div>
        <div class="mb-4">
            <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Feedback do Cliente</label>
            <textarea name="client_feedback" rows="2" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none"></textarea>
        </div>
        <div>
            <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Conclusão / Observações Finais</label>
            <textarea name="conclusion" rows="2" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none"></textarea>
        </div>
    `;
    container.appendChild(block);
}

async function submitVistorias() {
    const blocks = document.getElementById('vistoria-blocks').children;
    if(blocks.length === 0) return alert("Adicione pelo menos uma vistoria.");
    
    const data = [];
    for(let b of blocks) {
        const item = {};
        b.querySelectorAll('input, select, textarea').forEach(el => {
            item[el.name] = el.value;
        });
        data.push(item);
    }
    
    try {
        const res = await fetch('/api/gestao/atividades', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if(res.ok) {
            closeModal('modal-vistoria');
            loadItems('atividades');
        } else {
            alert("Erro ao salvar vistorias.");
        }
    } catch(e) {
        console.error(e);
        alert("Erro de conexão.");
    }
}

function editAtividade(id) {
    const item = currentAtividades.find(a => a.id === id);
    if(!item) return;
    
    document.getElementById('vistoria-blocks').innerHTML = '';
    addVistoriaBlock();
    
    const block = document.getElementById('vistoria-blocks').children[0];
    // Esconder lixo no modo edição de item único
    block.querySelector('.btn-remove-block').classList.add('hidden');
    
    block.querySelector('input[name="tech_responsible"]').value = item.tech || '';
    block.querySelector('input[name="client_name"]').value = item.client_name || '';
    block.querySelector('input[name="client_code"]').value = item.client_code || '';
    block.querySelector('input[name="type"]').value = item.type || '';
    block.querySelector('input[name="time"]').value = item.time || '';
    block.querySelector('select[name="quality_rating"]').value = item.quality || 'Excelente';
    block.querySelector('select[name="os_closure"]').value = item.os_closure || 'Sim';
    block.querySelector('textarea[name="client_feedback"]').value = item.feedback || '';
    block.querySelector('textarea[name="conclusion"]').value = item.conclusion || '';
    
    const submitBtn = document.getElementById('btn-save-vistoria');
    submitBtn.onclick = () => saveEditAtividade(id);
    submitBtn.innerHTML = '<i class="fa-solid fa-save"></i> Salvar Alteração';
    
    document.querySelector('#modal-vistoria button[onclick="addVistoriaBlock()"]').classList.add('hidden');
    openModal('modal-vistoria');
}

async function saveEditAtividade(id) {
    const block = document.getElementById('vistoria-blocks').children[0];
    const item = {};
    block.querySelectorAll('input, select, textarea').forEach(el => {
        item[el.name] = el.value;
    });
    
    try {
        const res = await fetch(`/api/gestao/atividades/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(item)
        });
        if(res.ok) {
            closeModal('modal-vistoria');
            loadItems('atividades');
        }
    } catch(e) { console.error(e); }
}

async function deleteAtividade(id) {
    if(!confirm("Deseja realmente excluir este registro de vistoria?")) return;
    try {
        const res = await fetch(`/api/gestao/atividades/${id}`, { method: 'DELETE' });
        if(res.ok) loadItems('atividades');
    } catch(e) { console.error(e); }
}

function downloadVistoriaPDF(id) {
    window.open(`/api/gestao/atividades/${id}/pdf`, '_blank');
}

function downloadMeetingPDF(id) {
    window.open(`/api/gestao/reunioes/${id}/pdf`, '_blank');
}

function downloadRFOPDF(id) {
    window.open(`/api/gestao/rfo/${id}/pdf`, '_blank');
}

function downloadEncerramentoPDF(id) {
    window.open(`/api/gestao/encerramento/${id}/pdf`, '_blank');
}

// --- ROTA EXATA JS ---
const tecnicos_js = {{ tecnicos_js_data | safe if tecnicos_js_data else '[]' }};
let rotaExataData = [];

function toggleRotaField(containerId, show) {
    const container = document.getElementById(containerId);
    if (show) {
        container.classList.remove('hidden');
    } else {
        container.classList.add('hidden');
    }
}

async function openModalRotaExata(id = null) {
    const modal = document.getElementById('modal-rota_exata');
    const container = document.getElementById('rota_exata_rows_container');
    const idInput = document.getElementById('rota_exata_id');
    
    container.innerHTML = '<div class="py-20 text-center"><i class="fa-solid fa-spinner fa-spin text-3xl text-purple-600"></i></div>';
    idInput.value = id || '';
    
    if (id) {
        try {
            const res = await fetch(`/api/gestao/rota_exata/${id}`);
            const data = await res.json();
            container.innerHTML = '';
            if (data.techs_data && data.techs_data.length > 0) {
                data.techs_data.forEach(t => addRotaExataRow(t));
            } else {
                addRotaExataRow();
            }
        } catch (e) {
            showToast("Erro ao carregar dados.", "error");
            closeModal('modal-rota_exata');
        }
    } else {
        container.innerHTML = '';
        addRotaExataRow();
    }
    
    openModal('modal-rota_exata');
}

function addRotaExataRow(data = null) {
    const container = document.getElementById('rota_exata_rows_container');
    const rowId = 'row-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    
    const div = document.createElement('div');
    div.id = rowId;
    div.className = "bg-white dark:bg-white/5 p-8 rounded-[2rem] border border-slate-900/10 dark:border-white/10 relative group/row animate-premium shadow-xl mb-8";
    
    const techOptions = tecnicos_js.map(t => `<option value="${t.id}" ${data && data.tech_id == t.id ? 'selected' : ''}>${t.username}</option>`).join('');
    const today = new Date().toISOString().split('T')[0];

    div.innerHTML = `
        <button type="button" onclick="removeRotaExataRow('${rowId}')" class="absolute -top-3 -right-3 w-10 h-10 bg-red-500 text-white rounded-2xl shadow-xl opacity-0 group-hover/row:opacity-100 transition-all flex items-center justify-center hover:bg-red-600 z-10 active:scale-90">
            <i class="fa-solid fa-trash-can text-sm"></i>
        </button>
        
        <div class="flex items-center gap-4 mb-8">
            <div class="w-12 h-12 rounded-2xl bg-purple-500/10 flex items-center justify-center text-purple-500 shadow-inner">
                <i class="fa-solid fa-route text-xl"></i>
            </div>
            <div>
                <h3 class="text-lg font-black text-slate-800 dark:text-white tracking-tight">Fiscalização de Rota</h3>
                <p class="text-[10px] text-slate-400 uppercase font-black tracking-[0.2em]">Prazos e Desvios</p>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1">
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Técnico</label>
                <select name="tech_id" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
                    <option value="">Selecione...</option>
                    ${techOptions}
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Dia Referente</label>
                <input type="date" name="supervision_date" value="${data ? data.supervision_date : today}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Saída Pátio</label>
                <input type="time" name="yard_departure_time" value="${data ? data.yard_departure_time || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Almoço (Início / Fim)</label>
                <div class="flex items-center gap-2">
                    <input type="time" name="lunch_start" value="${data ? data.lunch_start || '' : ''}" class="flex-1 bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-4 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
                    <input type="time" name="lunch_end" value="${data ? data.lunch_end || '' : ''}" class="flex-1 bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-4 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            <div class="bg-slate-50/50 dark:bg-white/5 p-6 rounded-[2rem] border border-slate-900/5 dark:border-white/5">
                <div class="flex items-center justify-between mb-4">
                    <span class="text-xs font-black text-slate-500 dark:text-gray-400 uppercase tracking-widest">Atraso na Saída?</span>
                    <label class="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" name="has_delay" class="sr-only peer" ${data && data.delay_reason ? 'checked' : ''} onchange="toggleRotaField('${rowId}-delay', this.checked)">
                        <div class="w-11 h-6 bg-slate-200 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:width-5 after:transition-all dark:border-gray-600 peer-checked:bg-amber-500"></div>
                    </label>
                </div>
                <div id="${rowId}-delay" class="${data && data.delay_reason ? '' : 'hidden'} animate-premium">
                    <textarea name="delay_reason" rows="2" class="w-full bg-white dark:bg-slate-900/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-amber-500/10 transition-all resize-none" placeholder="Qual o motivo do atraso?">${data ? data.delay_reason || '' : ''}</textarea>
                </div>
            </div>
            
            <div class="bg-slate-50/50 dark:bg-white/5 p-6 rounded-[2rem] border border-slate-900/5 dark:border-white/5">
                <div class="flex items-center justify-between mb-4">
                    <span class="text-xs font-black text-slate-500 dark:text-gray-400 uppercase tracking-widest">Desvio de Rota?</span>
                    <label class="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" name="has_deviation" class="sr-only peer" ${data && (data.route_deviation || data.identified_reason) ? 'checked' : ''} onchange="toggleRotaField('${rowId}-deviation', this.checked)">
                        <div class="w-11 h-6 bg-slate-200 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:width-5 after:transition-all dark:border-gray-600 peer-checked:bg-red-500"></div>
                    </label>
                </div>
                <div id="${rowId}-deviation" class="${data && (data.route_deviation || data.identified_reason) ? '' : 'hidden'} space-y-4 animate-premium">
                    <input type="text" name="route_deviation" value="${data ? data.route_deviation || '' : ''}" class="w-full bg-white dark:bg-slate-900/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-red-500/10 transition-all" placeholder="Local do desvio">
                    <textarea name="identified_reason" rows="2" class="w-full bg-white dark:bg-slate-900/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-red-500/10 transition-all resize-none" placeholder="Motivo identificado">${data ? data.identified_reason || '' : ''}</textarea>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Rota Planejada</label>
                <input type="text" name="planned_route" value="${data ? data.planned_route || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all" placeholder="Ex: Zona Norte - Equipe Alfa">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Observações Adicionais</label>
                <input type="text" name="observations" value="${data ? data.observations || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all" placeholder="Algum outro detalhe importante...">
            </div>
        </div>
    `;
    
    container.appendChild(div);
}

function removeRotaExataRow(rowId) {
    const container = document.getElementById('rota_exata_rows_container');
    if (container.children.length > 1) {
        document.getElementById(rowId).remove();
    } else {
        showToast("Você precisa de ao menos uma supervisão.", "info");
    }
}

async function submitRotaExataBulk() {
    const container = document.getElementById('rota_exata_rows_container');
    const rows = container.querySelectorAll('.group\\/row');
    
    const payload = {
        id: document.getElementById('rota_exata_id')?.value || null,
        techs: []
    };
    
    for (const row of rows) {
        const techSelect = row.querySelector('[name="tech_id"]');
        const tech_id = techSelect.value;
        const tech_name = techSelect.options[techSelect.selectedIndex]?.text || "N/A";
        if (!tech_id) continue;
        
        payload.techs.push({
            tech_id: tech_id,
            tech_name: tech_name,
            supervision_date: row.querySelector('[name="supervision_date"]').value,
            yard_departure_time: row.querySelector('[name="yard_departure_time"]').value,
            delay_reason: row.querySelector('[name="has_delay"]').checked ? row.querySelector('[name="delay_reason"]').value : "",
            route_deviation: row.querySelector('[name="has_deviation"]').checked ? row.querySelector('[name="route_deviation"]').value : "",
            identified_reason: row.querySelector('[name="has_deviation"]').checked ? row.querySelector('[name="identified_reason"]').value : "",
            lunch_start: row.querySelector('[name="lunch_start"]').value,
            lunch_end: row.querySelector('[name="lunch_end"]').value,
            planned_route: row.querySelector('[name="planned_route"]').value,
            observations: row.querySelector('[name="observations"]').value
        });
    }
    
    if (payload.techs.length === 0) return showToast("Adicione ao menos um técnico.", "error");
    
    const btn = document.getElementById('btn-save-rota');
    if (!btn) return;

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> Salvando...';
    
    try {
        const res = await fetch('/api/gestao/rota_exata', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const result = await res.json();
        if (result.success) {
            showToast("Supervisão de rota salva com sucesso!", "success");
            document.getElementById('modal-rota_exata').classList.add('hidden');
            loadItems('rota_exata');
        }
    } catch (err) {
        showToast("Erro ao salvar supervisão.", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-floppy-disk mr-2"></i> Salvar Supervisão';
    }
}


function editRota(id) {
    openModalRotaExata(id);
}

async function deleteRota(id) {
    if (!confirm("Tem certeza que deseja excluir esta supervisão?")) return;
    try {
        const res = await fetch(`/api/gestao/rota_exata/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast("Supervisão excluída!");
            loadItems('rota_exata');
        }
    } catch (e) {
        console.error(e);
        showToast("Erro ao excluir", "error");
    }
}

function downloadRotaPDF(id) {
    window.open(`/api/gestao/rota_exata/${id}/pdf`, '_blank');
}

// --- SUPERVISÃO DE CAMPO JS ---
let supervisaoData = [];

async function openModalSupervisao(id = null) {
    const modal = document.getElementById('modal-supervisao');
    const container = document.getElementById('supervisao_rows_container');
    const idInput = document.getElementById('supervisao_id');
    
    container.innerHTML = '<div class="py-20 text-center"><i class="fa-solid fa-spinner fa-spin text-3xl text-emerald-600"></i></div>';
    idInput.value = id || "";

    if (id) {
        try {
            const res = await fetch(`/api/gestao/supervisao/${id}`);
            const data = await res.json();
            container.innerHTML = '';
            if (data.techs_data && data.techs_data.length > 0) {
                data.techs_data.forEach(t => addSupervisaoRow(t));
            } else {
                addSupervisaoRow();
            }
        } catch (e) {
            showToast("Erro ao carregar supervisão.", "error");
            closeModal('modal-supervisao');
        }
    } else {
        container.innerHTML = '';
        addSupervisaoRow();
    }
    
    openModal('modal-supervisao');
}

function addSupervisaoRow(data = null) {
    const container = document.getElementById('supervisao_rows_container');
    const rowId = 'sup-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    
    const div = document.createElement('div');
    div.id = rowId;
    div.className = "bg-white dark:bg-white/5 p-8 rounded-[2rem] border border-slate-900/10 dark:border-white/10 relative group/row animate-premium shadow-xl mb-8";
    
    const techOptions = tecnicos_js.map(t => `<option value="${t.id}" ${data && data.tech_id == t.id ? 'selected' : ''}>${t.username}</option>`).join('');

    div.innerHTML = `
        <button type="button" onclick="removeSupervisaoRow('${rowId}')" class="absolute -top-3 -right-3 w-10 h-10 bg-red-500 text-white rounded-2xl shadow-xl opacity-0 group-hover/row:opacity-100 transition-all flex items-center justify-center hover:bg-red-600 z-10 active:scale-90">
            <i class="fa-solid fa-trash-can text-sm"></i>
        </button>
        
        <div class="flex items-center gap-4 mb-8">
            <div class="w-12 h-12 rounded-2xl bg-emerald-500/10 flex items-center justify-center text-emerald-500 shadow-inner">
                <i class="fa-solid fa-user-gear text-xl"></i>
            </div>
            <div>
                <h3 class="text-lg font-black text-slate-800 dark:text-white tracking-tight">Dados da Vistoria</h3>
                <p class="text-[10px] text-slate-400 uppercase font-black tracking-[0.2em]">Auditoria Individual</p>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Técnico</label>
                <select name="tech_id" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all">
                    <option value="">Selecione...</option>
                    ${techOptions}
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Local</label>
                <input type="text" name="location" value="${data ? data.location || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all" placeholder="Rua, Bairro, N°">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Horário</label>
                <input type="time" name="supervision_time" value="${data ? data.supervision_time || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all">
            </div>
            <div class="md:col-span-2 lg:col-span-3">
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Atividade Observada</label>
                <input type="text" name="activity" value="${data ? data.activity || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all" placeholder="O que o técnico estava fazendo?">
            </div>
        </div>

        <div class="mb-8">
            <p class="text-[10px] font-black text-slate-400 uppercase mb-4 tracking-[0.2em]">Checklist de Segurança</p>
            <div class="grid grid-cols-1 gap-3">
                ${[
                    { id: 'epi', label: 'EPI (Proteção Individual)' },
                    { id: 'epc', label: 'EPC (Proteção Coletiva)' },
                    { id: 'ladder_position', label: 'Posicionamento Escada' },
                    { id: 'car_position', label: 'Posicionamento Veículo' },
                    { id: 'uniform', label: 'Uniforme e Identificação' }
                ].map(field => `
                    <div class="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-2xl border border-slate-900/5 dark:border-white/5 bg-slate-50/50 dark:bg-white/5">
                        <span class="text-xs font-bold text-slate-600 dark:text-gray-300 mb-4 md:mb-0">${field.label}</span>
                        <div class="flex items-center gap-2">
                            <label class="flex-1 md:flex-none">
                                <input type="radio" name="${field.id}-${rowId}" value="OK" ${(!data || data[field.id] === 'OK') ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-emerald-500 peer-checked:border-emerald-500 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">OK</div>
                            </label>
                            <label class="flex-1 md:flex-none">
                                <input type="radio" name="${field.id}-${rowId}" value="IRR" ${data && data[field.id] === 'IRR' ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-red-500 peer-checked:border-red-500 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">IRR</div>
                            </label>
                            <label class="flex-1 md:flex-none">
                                <input type="radio" name="${field.id}-${rowId}" value="NA" ${data && data[field.id] === 'NA' ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-slate-400 peer-checked:border-slate-400 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">N/A</div>
                            </label>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>

        <div>
            <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Conclusão e Recomendações</label>
            <textarea name="conclusion" required placeholder="Observações finais para este técnico..." class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all h-32 resize-none">${data ? data.conclusion || '' : ''}</textarea>
        </div>
    `;
    
    container.appendChild(div);
}

function removeSupervisaoRow(rowId) {
    const container = document.getElementById('supervisao_rows_container');
    if (container.children.length > 1) {
        document.getElementById(rowId).remove();
    } else {
        showToast("Mantenha ao menos uma supervisão.", "info");
    }
}

async function submitSupervisaoBulk() {
    const container = document.getElementById('supervisao_rows_container');
    const rows = container.querySelectorAll('.group\\/row');
    
    const payload = {
        id: document.getElementById('supervisao_id')?.value || null,
        techs: []
    };
    
    for (const row of rows) {
        const rowId = row.id;
        const techSelect = row.querySelector('[name="tech_id"]');
        const tech_id = techSelect.value;
        const tech_name = techSelect.options[techSelect.selectedIndex]?.text || "N/A";
        if (!tech_id) continue;
        
        payload.techs.push({
            tech_id: tech_id,
            tech_name: tech_name,
            location: row.querySelector('[name="location"]').value,
            supervision_time: row.querySelector('[name="supervision_time"]').value,
            activity: row.querySelector('[name="activity"]').value,
            conclusion: row.querySelector('[name="conclusion"]').value,
            epi: row.querySelector(`[name="epi-${rowId}"]:checked`)?.value || 'OK',
            epc: row.querySelector(`[name="epc-${rowId}"]:checked`)?.value || 'OK',
            ladder_position: row.querySelector(`[name="ladder_position-${rowId}"]:checked`)?.value || 'OK',
            car_position: row.querySelector(`[name="car_position-${rowId}"]:checked`)?.value || 'OK',
            uniform: row.querySelector(`[name="uniform-${rowId}"]:checked`)?.value || 'OK'
        });
    }
    
    if (payload.techs.length === 0) return showToast("Adicione ao menos um técnico.", "error");
    
    const btn = document.getElementById('btn-save-supervisao');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i> Salvando...`;

    try {
        const res = await fetch('/api/gestao/supervisao', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const resData = await res.json();
        if (resData.success) {
            showToast("Supervisão única salva com sucesso!");
            closeModal('modal-supervisao');
            loadItems('supervisao');
        } else {
            throw new Error("Erro ao salvar");
        }
    } catch (e) {
        console.error(e);
        showToast("Erro ao salvar supervisão.", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

function editSupervisao(id) {
    openModalSupervisao(id);
}

async function deleteSupervisao(id) {
    if (!confirm("Deseja excluir esta supervisão?")) return;
    try {
        const res = await fetch(`/api/gestao/supervisao/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast("Supervisão excluída.");
            loadItems('supervisao');
        }
    } catch (e) {
        showToast("Erro ao excluir.", "error");
    }
}

function downloadSupervisaoPDF(id) {
    window.open(`/api/gestao/supervisao/${id}/pdf`, '_blank');
}

// Inicializa a aba com base na URL ou padrão
const urlParams = new URLSearchParams(window.location.search);
const initialTab = urlParams.get('tab') || 'equipes';
switchTab(initialTab);
