
let currentTab = 'dashboard';
const globalTecnicos = [
    
    { id: [], username: "[]" },
    
];
let currentAtividades = [];
let currentAnotacoes = [];
let currentAnotacaoTab = 'Geral';
let currentRFOs = [];
let currentGenerators = [];
let solicitacoesList = [];
let globalUsers = [];
let selectedTechsEncerramento = [];
const user_role = "[]";

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
    form.querySelector('[name="obs"]').value = "";
    const titleEl = document.getElementById('modal-tarefa-title');
    if(titleEl) titleEl.innerText = "Registrar Nova Tarefa";
    document.getElementById('task_show_on_calendar').checked = false;
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
    form.querySelector('[name="obs"]').value = t.obs || "";
    const titleEl = document.getElementById('modal-tarefa-title');
    if(titleEl) titleEl.innerText = "Editar Tarefa";
    document.getElementById('task_show_on_calendar').checked = !!t.show_on_calendar;
    
    document.getElementById('btn-save-tarefa').innerText = "Atualizar Tarefa";
    openModal('modal-tarefa');
}

async function deleteTarefa(id) {
    if(!confirm("Excluir esta tarefa?")) return;
    const res = await fetch(`/api/gestao/tarefas/${id}`, { method: 'DELETE' });
    if(res.ok) {
        loadItems('tarefas');
        if(calendar) calendar.refetchEvents();
    }
}

async function updateTarefaStatus(id, newStatus) {
    const res = await fetch(`/api/gestao/tarefas/${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ status: newStatus })
    });
    if(res.ok) {
        loadItems('tarefas');
        if(calendar) calendar.refetchEvents();
    }
}

// =============================================
// ATIVIDADES REALIZADAS (Campos Dinâmicos)
// =============================================
let arDynamicFieldCount = 0;

function openModalAtividadeRealizada() {
    const modalTitle = document.querySelector('#modal-atividade-realizada h3');
    if(modalTitle) modalTitle.innerText = "Nova Atividade Realizada";

    document.getElementById('atividade-realizada-id').value = '';
    document.getElementById('ar-title').value = '';
    document.getElementById('ar-date').value = new Date().toISOString().split('T')[0];
    document.getElementById('ar-obs').value = '';
    arDynamicFieldCount = 0;
    document.getElementById('dynamic-fields-container').innerHTML = `
        <div class="text-center py-6 text-slate-400">
            <i class="fa-solid fa-inbox text-2xl mb-2 opacity-30"></i>
            <p class="text-[10px] font-bold uppercase tracking-widest">Clique em "Novo Campo" para começar</p>
        </div>
    `;

    // Populate responsible select
    const sel = document.getElementById('ar-responsible');
    sel.innerHTML = '<option value="">Selecione um técnico</option>';
    if(typeof globalUsers !== 'undefined' && globalUsers.length > 0) {
        globalUsers.forEach(u => {
            sel.innerHTML += `<option value="${u.id}">${u.username}</option>`;
        });
    } else {
        loadUsers().then(() => {
            if(typeof globalUsers !== 'undefined') {
                globalUsers.forEach(u => {
                    sel.innerHTML += `<option value="${u.id}">${u.username}</option>`;
                });
            }
        });
    }

    openModal('modal-atividade-realizada');
}

async function editAtividadeRealizada(id) {
    try {
        const res = await fetch(`/api/gestao/atividades-realizadas?t=${Date.now()}`);
        const data = await res.json();
        const item = data.find(x => x.id === id);
        if(!item) return showToast('Atividade não encontrada.', 'error');

        // Clear dynamic fields container first
        const container = document.getElementById('dynamic-fields-container');
        container.innerHTML = '';
        arDynamicFieldCount = 0;

        // Populate fields
        document.getElementById('atividade-realizada-id').value = item.id;
        document.getElementById('ar-title').value = item.title;
        document.getElementById('ar-date').value = item.date || "";
        document.getElementById('ar-obs').value = item.obs || "";

        // Populate responsible select
        const sel = document.getElementById('ar-responsible');
        sel.innerHTML = '<option value="">Selecione um técnico</option>';
        if(typeof globalUsers !== 'undefined' && globalUsers.length > 0) {
            globalUsers.forEach(u => {
                sel.innerHTML += `<option value="${u.id}">${u.username}</option>`;
            });
            sel.value = item.responsible_id || "";
        } else {
            await loadUsers();
            if(typeof globalUsers !== 'undefined') {
                globalUsers.forEach(u => {
                    sel.innerHTML += `<option value="${u.id}">${u.username}</option>`;
                });
                sel.value = item.responsible_id || "";
            }
        }

        // Add dynamic fields
        if(item.fields && item.fields.length > 0) {
            item.fields.forEach(f => {
                addDynamicField(f.label, f.value);
            });
        } else {
            container.innerHTML = `
                <div class="text-center py-6 text-slate-400">
                    <i class="fa-solid fa-inbox text-2xl mb-2 opacity-30"></i>
                    <p class="text-[10px] font-bold uppercase tracking-widest">Clique em "Novo Campo" para começar</p>
                </div>
            `;
        }

        // Change modal title to Edit
        const modalTitle = document.querySelector('#modal-atividade-realizada h3');
        if(modalTitle) modalTitle.innerText = "Editar Atividade Realizada";

        openModal('modal-atividade-realizada');
    } catch(e) {
        console.error(e);
        showToast('Erro ao carregar dados da atividade.', 'error');
    }
}

function addDynamicField(label = '', value = '') {
    const container = document.getElementById('dynamic-fields-container');

    // Remove empty state placeholder if present
    const emptyState = container.querySelector('.text-center');
    if(emptyState) emptyState.remove();

    const idx = arDynamicFieldCount++;
    const fieldHTML = `
        <div class="dynamic-field-row bg-white dark:bg-gray-800/50 border border-slate-900/5 dark:border-white/5 rounded-xl p-4 relative group animate-premium" data-field-idx="${idx}">
            <button type="button" onclick="removeDynamicField(${idx})" class="absolute -top-2 -right-2 w-7 h-7 bg-red-500 hover:bg-red-600 text-white rounded-full flex items-center justify-center text-xs shadow-lg opacity-0 group-hover:opacity-100 transition-all" title="Remover campo">
                <i class="fa-solid fa-xmark"></i>
            </button>
            <div class="mb-3">
                <label class="block text-[9px] font-bold text-emerald-600 uppercase tracking-widest mb-1">Nome do Campo</label>
                <input aria-label="Ex: Serviço Realizado, Material Utilizado..." type="text" class="ar-field-label w-full bg-slate-50 dark:bg-gray-700 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-sm font-bold outline-none focus:ring-2 focus:ring-emerald-500/20 dark:text-white" placeholder="Ex: Serviço Realizado, Material Utilizado..." value="${label}">
            </div>
            <div>
                <label class="block text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-1">Conteúdo</label>
                <textarea class="ar-field-value w-full bg-slate-50 dark:bg-gray-700 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-emerald-500/20 resize-none dark:text-white" rows="3" placeholder="Descreva as informações deste campo...">${value}</textarea>
            </div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', fieldHTML);
}

function removeDynamicField(idx) {
    const row = document.querySelector(`.dynamic-field-row[data-field-idx="${idx}"]`);
    if(row) {
        row.style.transition = 'all 0.3s ease';
        row.style.opacity = '0';
        row.style.transform = 'scale(0.95) translateY(-10px)';
        setTimeout(() => {
            row.remove();
            const container = document.getElementById('dynamic-fields-container');
            if(container.querySelectorAll('.dynamic-field-row').length === 0) {
                container.innerHTML = `
                    <div class="text-center py-6 text-slate-400">
                        <i class="fa-solid fa-inbox text-2xl mb-2 opacity-30"></i>
                        <p class="text-[10px] font-bold uppercase tracking-widest">Clique em "Novo Campo" para começar</p>
                    </div>
                `;
            }
        }, 300);
    }
}

async function submitAtividadeRealizada() {
    const title = document.getElementById('ar-title').value.trim();
    if(!title) return showToast('Preencha o título da atividade.', 'warning');

    const fields = [];
    document.querySelectorAll('.dynamic-field-row').forEach(row => {
        const label = row.querySelector('.ar-field-label').value.trim();
        const value = row.querySelector('.ar-field-value').value.trim();
        if(label) {
            fields.push({ label, value });
        }
    });

    if(fields.length === 0) return showToast('Adicione pelo menos um campo à atividade.', 'warning');

    const payload = {
        id: document.getElementById('atividade-realizada-id').value || null,
        title: title,
        responsible_id: document.getElementById('ar-responsible').value || null,
        date: document.getElementById('ar-date').value || null,
        fields: fields,
        obs: document.getElementById('ar-obs').value.trim() || null
    };

    try {
        const res = await fetch('/api/gestao/atividades-realizadas', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(res.ok) {
            showToast('Atividade realizada salva com sucesso!', 'success');
            closeModal('modal-atividade-realizada');
            loadAtividadesRealizadas();
        } else {
            const err = await res.json();
            showToast(err.error || 'Erro ao salvar atividade.', 'error');
        }
    } catch(e) {
        console.error(e);
        showToast('Erro de conexão ao salvar atividade.', 'error');
    }
}

async function loadAtividadesRealizadas() {
    try {
        const res = await fetch(`/api/gestao/atividades-realizadas?t=${Date.now()}`);
        const data = await res.json();
        const container = document.getElementById('list-atividades-realizadas');
        if(!container) return;

        const badgeEl = document.getElementById('badgeSubTabAtividades');
        if(badgeEl) badgeEl.innerText = data.length;

        if(data.length === 0) {
            container.innerHTML = `
                <div class="py-10 flex flex-col items-center justify-center text-slate-400 col-span-full">
                    <i class="fa-solid fa-folder-open text-3xl mb-3 opacity-20"></i>
                    <p class="text-xs font-medium">Nenhuma atividade registrada ainda</p>
                </div>
            `;
            return;
        }

        container.innerHTML = data.map(item => {
            const fieldsPreview = item.fields.slice(0, 2).map(f =>
                `<div class="text-[10px] text-slate-600 dark:text-gray-300 leading-tight truncate"><strong class="text-emerald-600">${f.label}:</strong> ${f.value || '—'}</div>`
            ).join('');

            return `
                <div class="backdrop-blur-md bg-white/70 dark:bg-white/10 p-5 rounded-[2.0rem] border border-slate-900/10 dark:border-white/10 shadow-xl hover:shadow-2xl hover:scale-[1.02] transition-all duration-300 relative overflow-hidden flex flex-col justify-between h-full group animate-premium">
                    <!-- Top border indicator -->
                    <div class="absolute top-0 left-0 w-full h-[4px] bg-gradient-to-r from-emerald-600 to-teal-500"></div>

                    <div>
                        <div class="flex justify-between items-center mb-3">
                            <h2 class="text-xs font-black text-slate-800 dark:text-white flex items-center gap-1.5">
                                <i class="fa-solid fa-clipboard-check text-emerald-500"></i>
                                Atividade
                            </h2>
                            <span class="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-[8px] font-black uppercase tracking-wider">
                                Concluída
                            </span>
                        </div>

                        <h3 class="text-xs font-black text-slate-800 dark:text-white tracking-tight mb-2 truncate max-w-[220px]" title="${item.title}">
                            ${item.title}
                        </h3>

                        <div class="space-y-1.5 mb-4 text-[11px] font-bold text-slate-600 dark:text-gray-300">
                            <p class="flex items-center gap-1.5">
                                <i class="fa-solid fa-user-gear text-[10px] text-slate-400 w-3 text-center"></i>
                                <span>${item.responsible_name}</span>
                            </p>
                            <p class="flex items-center gap-1.5">
                                <i class="fa-solid fa-calendar text-[10px] text-slate-400 w-3 text-center"></i>
                                <span>${item.date ? new Date(item.date + 'T00:00:00').toLocaleDateString() : 'N/D'}</span>
                            </p>
                        </div>

                        <div class="bg-slate-900/5 dark:bg-white/5 p-3 rounded-xl border border-slate-900/5 dark:border-white/5 mb-4">
                            <p class="text-slate-500 dark:text-slate-400 text-[8px] font-black uppercase tracking-wider mb-1">Resumo de Campos</p>
                            <div class="space-y-1">
                                ${fieldsPreview || '<span class="text-slate-400 text-[10px] italic">Sem campos registrados</span>'}
                            </div>
                        </div>
                    </div>

                    <div class="flex flex-col gap-2 pt-2 border-t border-slate-900/10 dark:border-white/10 mt-auto">
                        <div class="flex items-center gap-2">
                            <button onclick="window.open('/api/gestao/atividades-realizadas/${item.id}/pdf', '_blank')" class="flex-1 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-[9px] font-black uppercase tracking-wider transition-all flex items-center justify-center gap-1 active:scale-95 shadow-lg shadow-emerald-500/10">
                                <i class="fa-solid fa-file-pdf"></i> PDF
                            </button>
                            <button onclick="showAtividadeRealizadaDetalhes(${item.id})" class="flex-1 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-[9px] font-black uppercase tracking-wider transition-all flex items-center justify-center gap-1 active:scale-95 shadow-lg shadow-blue-500/10">
                                <i class="fa-solid fa-eye"></i> Detalhes
                            </button>
                        </div>

                        <div class="flex items-center justify-between gap-2 bg-slate-50 dark:bg-gray-800/40 p-1 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <button onclick="editAtividadeRealizada(${item.id})" class="flex-1 py-1 flex items-center justify-center text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded transition-all active:scale-95" title="Editar">
                                <i class="fa-solid fa-pen text-[9px] mr-1"></i> <span class="text-[8px] font-black uppercase">Editar</span>
                            </button>
                            <button onclick="deleteAtividadeRealizada(${item.id})" class="flex-1 py-1 flex items-center justify-center text-red-500 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-all active:scale-95" title="Excluir">
                                <i class="fa-solid fa-trash-can text-[9px] mr-1"></i> <span class="text-[8px] font-black uppercase">Excluir</span>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    } catch(e) {
        console.error('Erro ao carregar atividades realizadas:', e);
    }
}

async function deleteAtividadeRealizada(id) {
    if(!confirm('Excluir esta atividade realizada?')) return;
    try {
        const res = await fetch(`/api/gestao/atividades-realizadas/${id}`, { method: 'DELETE' });
        if(res.ok) {
            showToast('Atividade excluída com sucesso.', 'success');
            loadAtividadesRealizadas();
        } else {
            showToast('Erro ao excluir atividade.', 'error');
        }
    } catch(e) {
        console.error(e);
    }
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
        'relatorios': { label: 'Relatórios Gerenciais', sub: 'Exportação de dados e KPIs consolidados.', icon: 'fa-file-pdf' },
        'powerbi': { label: 'Dashboard Power BI', sub: 'Visão de performance operacional, indicadores de campo e frota.', icon: 'fa-chart-pie' }
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
        loadAtividadesRealizadas();
        switchSubTab('tarefas');
    }
    if(tabId === 'geradores') loadItems('geradores');
    if(tabId === 'rota_exata') loadItems('rota_exata');
    if(tabId === 'supervisao') loadItems('supervisao');
    if(tabId === 'solicitacoes') loadItems('solicitacoes');
    if(tabId === 'treinamentos') loadLMSCourses();
    if(tabId === 'relatorios') initRelatoriosTab();
    if(tabId === 'powerbi') initPowerBITab();
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
        const badgeEl = document.getElementById('badgeSubTabTarefas');
        if(badgeEl) badgeEl.innerText = data.length;

        if(data.length === 0) {
            container.innerHTML = `
                <div class="py-10 flex flex-col items-center justify-center text-slate-400 col-span-full">
                    <i class="fa-solid fa-folder-open text-3xl mb-3 opacity-20"></i>
                    <p class="text-xs font-medium">Nenhuma tarefa registrada ainda</p>
                </div>
            `;
            return;
        }

        container.innerHTML = data.map(i => {
            let priorityColor = 'text-slate-400 bg-slate-100 dark:bg-slate-800/50';
            let priorityBorder = 'bg-gradient-to-r from-slate-500 to-slate-400';
            if(i.priority === 'Alta') {
                priorityColor = 'text-orange-600 bg-orange-100 dark:bg-orange-950/20';
                priorityBorder = 'bg-gradient-to-r from-orange-600 to-amber-500';
            } else if(i.priority === 'Crítica') {
                priorityColor = 'text-red-600 bg-red-100 dark:bg-red-950/20 animate-pulse';
                priorityBorder = 'bg-gradient-to-r from-red-600 to-rose-500';
            } else if(i.priority === 'Baixa') {
                priorityColor = 'text-blue-600 bg-blue-100 dark:bg-blue-950/20';
                priorityBorder = 'bg-gradient-to-r from-blue-600 to-sky-500';
            }

            let statusColor = 'bg-slate-500';
            if(i.status === 'Em Andamento') statusColor = 'bg-indigo-500';
            else if(i.status === 'Concluída') statusColor = 'bg-emerald-500';

            return `
                <div class="backdrop-blur-md bg-white/70 dark:bg-white/10 p-5 rounded-[2.0rem] border border-slate-900/10 dark:border-white/10 shadow-xl hover:shadow-2xl hover:scale-[1.02] transition-all duration-300 relative overflow-hidden flex flex-col justify-between h-full group animate-premium">
                    <div class="absolute top-0 left-0 w-full h-[4px] ${priorityBorder}"></div>
                    
                    <div>
                        <div class="flex justify-between items-start mb-3 gap-2">
                            <span class="px-2 py-0.5 rounded-md ${priorityColor} text-[8px] font-black uppercase tracking-wider">${i.priority}</span>
                            <span class="px-2 py-0.5 rounded-md text-white ${statusColor} text-[8px] font-black uppercase tracking-wider">${i.status}</span>
                        </div>
                        
                        <h3 class="text-xs font-black text-slate-800 dark:text-white tracking-tight mb-2 truncate max-w-[220px]" title="${i.title}">
                            ${i.title}
                        </h3>
                        
                        <div class="space-y-1.5 mb-4 text-[11px] font-bold text-slate-600 dark:text-gray-300">
                            <p class="flex items-center gap-1.5">
                                <i class="fa-solid fa-user-gear text-[10px] text-slate-400 w-3 text-center"></i>
                                <span>${i.responsible}</span>
                            </p>
                            <p class="flex items-center gap-1.5">
                                <i class="fa-solid fa-calendar text-[10px] text-slate-400 w-3 text-center"></i>
                                <span>${i.deadline ? new Date(i.deadline + 'T00:00:00').toLocaleDateString() : 'N/D'}</span>
                            </p>
                        </div>

                        <div class="bg-slate-900/5 dark:bg-white/5 p-3 rounded-xl border border-slate-900/5 dark:border-white/5 mb-4">
                            <p class="text-slate-500 dark:text-slate-400 text-[8px] font-black uppercase tracking-wider mb-1">Descrição</p>
                            <p class="text-slate-700 dark:text-slate-300 text-[11px] leading-relaxed font-medium line-clamp-3">
                                ${i.description || 'Sem descrição.'}
                            </p>
                        </div>
                    </div>

                    <div class="flex flex-col gap-2 pt-2 border-t border-slate-900/10 dark:border-white/10 mt-auto">
                        <div class="flex items-center gap-2">
                            ${i.status === 'Pendente' ? `
                                <button onclick="updateTarefaStatus(${i.id}, 'Em Andamento')" class="flex-1 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-black text-[9px] uppercase tracking-wider transition-all flex items-center justify-center gap-1 active:scale-95">
                                    <i class="fa-solid fa-play text-[9px]"></i> Iniciar
                                </button>
                            ` : ''}
                            ${i.status === 'Em Andamento' ? `
                                <button onclick="updateTarefaStatus(${i.id}, 'Concluída')" class="flex-1 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-black text-[9px] uppercase tracking-wider transition-all flex items-center justify-center gap-1 active:scale-95">
                                    <i class="fa-solid fa-check text-[9px]"></i> Concluir
                                </button>
                            ` : ''}
                            ${i.status === 'Concluída' ? `
                                <div class="flex-1 py-2 rounded-xl bg-emerald-100 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 font-black text-[9px] uppercase tracking-wider flex items-center justify-center gap-1">
                                    <i class="fa-solid fa-circle-check text-[10px]"></i> Pronto
                                </div>
                            ` : ''}

                            <button onclick="showTarefaDetalhes(${i.id})" class="flex-1 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-black text-[9px] uppercase tracking-wider transition-all flex items-center justify-center gap-1 active:scale-95">
                                <i class="fa-solid fa-eye text-[9px]"></i> Detalhes
                            </button>
                        </div>

                        <div class="flex items-center justify-between gap-2 bg-slate-50 dark:bg-gray-800/40 p-1 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <button onclick="editTarefa(${i.id})" class="flex-1 py-1 flex items-center justify-center text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded transition-all active:scale-95" title="Editar Tarefa">
                                <i class="fa-solid fa-pen text-[9px] mr-1"></i> <span class="text-[8px] font-black uppercase">Editar</span>
                            </button>
                            <button onclick="deleteTarefa(${i.id})" class="flex-1 py-1 flex items-center justify-center text-red-500 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-all active:scale-95" title="Excluir Tarefa">
                                <i class="fa-solid fa-trash-can text-[9px] mr-1"></i> <span class="text-[8px] font-black uppercase">Excluir</span>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    } else if(slug === 'escalas') {
        const resE = await fetch(`/api/gestao/escalas?view=list&t=${Date.now()}`);
        const scales = await resE.json();
        container.innerHTML = scales.map(s => {
            let names = 'Escala por Técnico';
            if(s.team_ids) {
                const ids = s.team_ids.split(',').map(x => parseInt(x));
                const matchedTeams = globalEquipes.filter(e => ids.includes(e.id)).map(e => e.name);
                if(matchedTeams.length > 0) {
                    names = matchedTeams.join(' + ');
                }
            }
            return `
            <div class="flex items-center justify-between p-4 bg-white/70 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-xl group transition-all hover:border-purple-500/30">
                <div class="flex flex-1 items-center gap-4">
                    <div class="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center text-purple-600">
                        <i class="fa-solid fa-calendar-check"></i>
                    </div>
                    <div>
                        <div class="text-sm font-bold text-slate-800 dark:text-white">${new Date(s.date + 'T00:00:00').toLocaleDateString()} - ${s.type.toUpperCase()}</div>
                        <div class="text-[10px] text-purple-600 dark:text-purple-400 font-bold">${names}</div>
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
        container.innerHTML = data.map(i => {
            const hasMultiple = i.blocks && i.blocks.length > 1;
            
            // Renderiza o drawer expansível de acordo
            let drawerContent = '';
            if (hasMultiple) {
                drawerContent = `
                    <div class="space-y-3">
                        <p class="text-[9px] font-black text-slate-400 uppercase tracking-widest border-b border-slate-900/5 dark:border-white/5 pb-1">Vistorias Integradas (${i.blocks.length} técnicos)</p>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left border-collapse text-[11px]">
                                <thead>
                                    <tr class="border-b border-slate-900/10 dark:border-white/10 text-slate-400 font-bold uppercase tracking-wider">
                                        <th class="py-2 pr-4">Técnico</th>
                                        <th class="py-2 pr-4">Cliente</th>
                                        <th class="py-2 pr-4">Atividade</th>
                                        <th class="py-2 pr-4">Qualidade</th>
                                        <th class="py-2 pr-4">O.S. Fechada</th>
                                        <th class="py-2">Feedback & Observações</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${i.blocks.map(b => `
                                        <tr class="border-b border-slate-900/5 dark:border-white/5 last:border-0 hover:bg-slate-50 dark:hover:bg-white/5 transition-colors">
                                            <td class="py-2 pr-4 font-bold text-slate-700 dark:text-gray-300">${b.tech_responsible || 'N/A'}</td>
                                            <td class="py-2 pr-4 text-slate-600 dark:text-gray-400">
                                                <div class="font-semibold">${b.client_name || 'N/A'}</div>
                                                <div class="text-[9px] text-slate-400">Cód: ${b.client_code || 'N/A'}</div>
                                            </td>
                                            <td class="py-2 pr-4"><span class="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded text-[9px] font-bold">${b.type || 'Vistoria'}</span></td>
                                            <td class="py-2 pr-4"><span class="px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 rounded text-[9px] font-bold">${b.quality_rating || 'Excelente'}</span></td>
                                            <td class="py-2 pr-4 font-semibold">${b.os_closure || 'N/A'}</td>
                                            <td class="py-2 max-w-[250px] truncate" title="Feedback: ${b.client_feedback || 'Sem feedback'}\nObs: ${b.conclusion || 'Sem conclusão'}">
                                                <div class="truncate text-slate-500"><i class="fa-solid fa-comment-dots text-purple-400"></i> ${b.client_feedback || 'Sem feedback'}</div>
                                                <div class="truncate text-[9px] text-slate-400"><i class="fa-solid fa-check-double text-slate-400"></i> ${b.conclusion || 'Sem conclusão'}</div>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            } else {
                drawerContent = `
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Feedback do Cliente</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.client_feedback || i.feedback || 'Sem feedback registrado'}</p>
                        </div>
                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Conclusão / Observações Finais</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.conclusion || 'Nenhuma observação final'}</p>
                        </div>
                    </div>
                `;
            }

            return `
            <div class="bg-white dark:bg-gray-900 rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-md hover:border-purple-500/20 dark:hover:border-purple-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden animate-premium">
                <!-- Sleek horizontal row layout -->
                <div class="flex flex-wrap md:flex-nowrap items-center justify-between p-3.5 gap-3">
                    
                    <!-- Left: Icon + Main Info -->
                    <div class="flex items-center gap-3 flex-1 min-w-[280px]">
                        <div class="w-10 h-10 rounded-xl bg-purple-50 dark:bg-purple-900/20 text-purple-600 flex items-center justify-center text-sm shadow-inner shrink-0">
                            <i class="fa-solid fa-clipboard-check"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-2 mb-0.5">
                                <span class="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full text-[9px] font-black uppercase tracking-wider shrink-0">${i.type || 'Vistoria'}</span>
                                <span class="text-[10px] text-slate-400 font-bold shrink-0">${i.date ? new Date(i.date + 'T00:00:00').toLocaleDateString() : '-'} ${i.time || ''}</span>
                            </div>
                            <h4 class="font-extrabold text-slate-800 dark:text-white text-xs truncate leading-tight">${i.client_name || 'Sem nome'}</h4>
                            <p class="text-[9px] text-slate-400 font-black uppercase tracking-widest leading-none mt-0.5">CÓD: ${i.client_code || '-'}</p>
                        </div>
                    </div>

                    <!-- Middle: Technical Quality -->
                    <div class="flex items-center gap-4 shrink-0 px-4">
                        <div class="flex flex-col">
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">Avaliação</span>
                            <span class="px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 dark:text-emerald-400 rounded-md text-[9px] font-black uppercase tracking-wider w-fit mt-0.5">${i.quality || 'Excelente'}</span>
                        </div>
                        <div class="flex flex-col max-w-[150px]">
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">Responsável</span>
                            <span class="text-xs font-bold text-slate-700 dark:text-gray-300 mt-0.5 truncate" title="${i.tech || 'Não informado'}">${i.tech || 'Não informado'}</span>
                        </div>
                    </div>

                    <!-- Right: Actions -->
                    <div class="flex items-center gap-2 shrink-0">
                        <button onclick="downloadVistoriaPDF(${i.id})" class="px-3 py-1.5 bg-purple-50 hover:bg-purple-100 text-purple-600 rounded-lg text-[10px] font-bold flex items-center gap-1.5 transition-all">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                        <button onclick="editAtividade(${i.id})" class="w-8 h-8 flex items-center justify-center bg-blue-50 dark:bg-blue-900/30 text-blue-500 rounded-full hover:bg-blue-100" title="Editar">
                            <i class="fa-solid fa-pen text-[10px]"></i>
                        </button>
                        <button onclick="deleteAtividade(${i.id})" class="w-8 h-8 flex items-center justify-center bg-red-50 dark:bg-red-900/30 text-red-500 rounded-full hover:bg-red-100" title="Excluir">
                            <i class="fa-solid fa-trash text-[10px]"></i>
                        </button>
                        <button onclick="this.closest('.group').querySelector('.atividade-expanded-row').classList.toggle('hidden')" class="w-8 h-8 flex items-center justify-center bg-slate-50 dark:bg-gray-800 text-slate-500 rounded-full hover:bg-slate-100" title="Ver Detalhes">
                            <i class="fa-solid fa-chevron-down text-[10px]"></i>
                        </button>
                    </div>
                </div>

                <!-- Expanded Drawer Content -->
                <div class="atividade-expanded-row hidden border-t border-slate-900/5 dark:border-white/5 bg-slate-50/50 dark:bg-gray-900/30 p-4 animate-premium">
                    ${drawerContent}
                </div>
            </div>`;
        }).join('');
    } else if(slug === 'reunioes') {
        container.innerHTML = data.map(i => {
            const isCompleted = i.status === 'Concluída';
            const statusClass = isCompleted 
                ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400' 
                : 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400';
            
            // Format dates
            let dateFormatted = 'N/A';
            if (i.date) {
                const dateParts = i.date.split('-');
                if (dateParts.length === 3) {
                    dateFormatted = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
                }
            }

            return `
            <div class="bg-white dark:bg-gray-900 rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-md hover:border-purple-500/20 dark:hover:border-purple-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden">
                <!-- Sleek horizontal row layout -->
                <div class="flex flex-wrap md:flex-nowrap items-center justify-between p-3.5 gap-3">
                    
                    <!-- Left: Compact colored indicator + Date & Time Info -->
                    <div class="flex items-center gap-3 min-w-[150px]">
                        <!-- Vertical status line -->
                        <div class="w-1 h-8 rounded-full ${isCompleted ? 'bg-emerald-500' : 'bg-purple-500 animate-pulse'}"></div>
                        <div class="flex flex-col">
                            <span class="text-[11px] font-extrabold text-slate-800 dark:text-white leading-tight flex items-center gap-1">
                                <i class="fa-solid fa-clock text-purple-500 text-[10px]"></i> ${i.time}
                            </span>
                            <span class="text-[9px] font-semibold text-slate-400 dark:text-gray-500 uppercase">${dateFormatted}</span>
                        </div>
                    </div>

                    <!-- Center-Left: Subject Title (Main Focus) -->
                    <div class="flex-1 min-w-[200px]">
                        <div class="flex items-center gap-2 mb-0.5">
                            <span class="px-2 py-0.5 rounded-md text-[8px] font-black uppercase tracking-wider ${statusClass}">
                                ${i.status}
                            </span>
                            <span class="text-[9px] font-bold text-slate-400 dark:text-gray-500 uppercase tracking-wider">${i.title}</span>
                        </div>
                        <h4 class="font-bold text-xs text-slate-800 dark:text-white leading-snug group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors ${isCompleted ? 'line-through opacity-70' : ''}">${i.subject}</h4>
                    </div>

                    <!-- Center-Right: Quick Metadata Tags -->
                    <div class="flex items-center gap-3 text-[10px] text-slate-500 dark:text-gray-400 min-w-[220px]">
                        <!-- Location tag -->
                        <div class="flex items-center gap-1 px-2 py-0.5 bg-slate-50 dark:bg-gray-800 rounded-md border border-slate-900/5 dark:border-white/5 truncate max-w-[110px]" title="${i.location || 'Não especificado'}">
                            <i class="fa-solid fa-location-dot text-indigo-400 text-[9px]"></i>
                            <span class="truncate font-medium">${i.location || 'N/A'}</span>
                        </div>
                        <!-- Leader tag -->
                        <div class="flex items-center gap-1 px-2 py-0.5 bg-slate-50 dark:bg-gray-800 rounded-md border border-slate-900/5 dark:border-white/5 truncate max-w-[110px]" title="Condutor: ${i.responsible || 'N/A'}">
                            <i class="fa-solid fa-user-tie text-blue-400 text-[9px]"></i>
                            <span class="truncate font-medium">${i.responsible || 'N/A'}</span>
                        </div>
                    </div>

                    <!-- Right: Expand Details button + Action buttons -->
                    <div class="flex items-center gap-2 justify-end">
                        <!-- Accordion toggle button -->
                        <button onclick="const details = this.closest('.group').querySelector('.reuniao-expanded-row'); details.classList.toggle('hidden'); this.querySelector('i').classList.toggle('rotate-180')" 
                            class="px-2.5 py-1 bg-slate-50 dark:bg-gray-800 hover:bg-slate-100 dark:hover:bg-gray-700 text-[9px] font-bold text-slate-500 dark:text-gray-400 rounded-lg border border-slate-900/5 dark:border-white/5 transition-all flex items-center gap-1">
                            <span>Ata</span>
                            <i class="fa-solid fa-chevron-down transition-transform duration-200 text-[8px]"></i>
                        </button>

                        <div class="flex items-center gap-1 bg-slate-50 dark:bg-gray-800 p-0.5 rounded-lg border border-slate-900/5 dark:border-white/5">
                            <button onclick="downloadMeetingPDF(${i.id})" class="w-7 h-7 flex items-center justify-center text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/20 rounded-md transition-colors" title="Gerar ATA em PDF">
                                <i class="fa-solid fa-file-pdf text-[10px]"></i>
                            </button>
                            <button onclick="editReuniao(${i.id})" class="w-7 h-7 flex items-center justify-center text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-950/20 rounded-md transition-colors" title="Editar">
                                <i class="fa-solid fa-pen text-[10px]"></i>
                            </button>
                            <button onclick="deleteReuniao(${i.id})" class="w-7 h-7 flex items-center justify-center text-red-500 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-md transition-colors" title="Excluir">
                                <i class="fa-solid fa-trash text-[10px]"></i>
                            </button>
                        </div>

                        ${!isCompleted ? `
                            <button onclick="updateStatus('reunioes', ${i.id}, 'Concluída')" class="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-[9px] font-bold transition-all shadow-sm active:scale-95 flex items-center gap-1">
                                <i class="fa-solid fa-circle-check text-[9px]"></i> Realizada
                            </button>
                        ` : ''}
                    </div>

                </div>

                <!-- Collapsible Ata Details Drawer -->
                <div class="reuniao-expanded-row hidden px-4 pb-4 pt-1 border-t border-dashed border-slate-200 dark:border-white/10 bg-slate-50/50 dark:bg-gray-900/30 transition-all duration-300">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-2">
                        <!-- Objective -->
                        <div class="bg-purple-50 dark:bg-purple-950/20 p-2.5 rounded-xl border border-purple-500/10">
                            <span class="text-[9px] font-bold text-purple-600 dark:text-purple-400 uppercase tracking-wider block mb-0.5">Objetivo principal</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.objective || '<span class="text-slate-400 italic text-[10px]">Nenhum objetivo registrado</span>'}</p>
                        </div>

                        <!-- Summary -->
                        <div class="bg-slate-50 dark:bg-gray-800/40 p-2.5 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">Resumo da ata</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed italic">${i.summary || '<span class="text-slate-400 text-[10px]">Nenhum resumo registrado</span>'}</p>
                        </div>

                        <!-- Actions -->
                        <div class="bg-amber-50 dark:bg-amber-950/20 p-2.5 rounded-xl border border-amber-500/10">
                            <span class="text-[9px] font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider block mb-1">Encaminhamentos / Ações</span>
                            <div class="space-y-1">
                                ${i.actions ? i.actions.split('\n').map(action => action.trim() ? `
                                    <div class="flex items-start gap-1.5 text-xs text-slate-600 dark:text-gray-300">
                                        <i class="fa-solid fa-square-check text-amber-500 mt-0.5 text-[10px]"></i>
                                        <span>${action}</span>
                                    </div>
                                ` : '').join('') : '<span class="text-slate-400 text-[10px] italic">Nenhum encaminhamento registrado</span>'}
                            </div>
                        </div>

                        <!-- Participants -->
                        <div>
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">Técnicos Presentes</span>
                            <div class="flex flex-wrap gap-1">
                                ${i.participant_names ? i.participant_names.split(',').map(name => `
                                    <span class="px-2 py-0.5 bg-blue-50 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 rounded-md text-[10px] font-medium flex items-center gap-1">
                                        <i class="fa-solid fa-user text-[8px]"></i> ${name.trim()}
                                    </span>
                                `).join('') : '<span class="text-slate-400 text-[10px] italic">Nenhum participante registrado</span>'}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            `;
        }).join('');
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
            <div class="bg-white dark:bg-gray-900 rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm hover:shadow-md hover:border-red-500/20 dark:hover:border-red-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden animate-premium">
                <!-- Sleek horizontal row layout -->
                <div class="flex flex-wrap md:flex-nowrap items-center justify-between p-3.5 gap-3">
                    
                    <!-- Left: Icon + Main Info -->
                    <div class="flex items-center gap-3 flex-1 min-w-[280px]">
                        <div class="w-10 h-10 rounded-xl bg-red-50 dark:bg-red-900/20 text-red-600 flex items-center justify-center text-sm shadow-inner shrink-0">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-2 mb-0.5">
                                <span class="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-600 rounded-full text-[9px] font-black uppercase tracking-wider shrink-0">${i.status || 'FINALIZADO'}</span>
                                <span class="text-[10px] text-slate-400 font-bold shrink-0">${i.date ? new Date(i.date + 'T00:00:00').toLocaleDateString() : '-'}</span>
                            </div>
                            <h4 class="font-extrabold text-slate-800 dark:text-white text-xs truncate leading-tight">${i.problem_type || 'Falha Operacional'}</h4>
                            <p class="text-[9px] text-slate-400 font-black uppercase tracking-widest leading-none mt-0.5">PROTOCOLO: ${i.number || '-'}</p>
                        </div>
                    </div>

                    <!-- Middle: Location & Technician -->
                    <div class="flex items-center gap-4 shrink-0 px-4">
                        <div class="flex flex-col">
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">Responsável</span>
                            <span class="text-xs font-bold text-slate-700 dark:text-gray-300 mt-0.5">${i.tech || i.tech_responsible || 'Sem técnico'}</span>
                        </div>
                        <div class="flex flex-col">
                            <span class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">Cidade / Bairro</span>
                            <span class="text-xs font-semibold text-slate-500 mt-0.5">${i.city || 'N/A'} - ${i.neighborhood || 'N/A'}</span>
                        </div>
                    </div>

                    <!-- Right: Actions -->
                    <div class="flex items-center gap-2 shrink-0">
                        <button onclick="downloadRFOPDF(${i.id})" class="px-3 py-1.5 bg-red-50 hover:bg-red-100 text-red-600 dark:bg-red-950/20 dark:text-red-400 rounded-lg text-[10px] font-bold flex items-center gap-1.5 transition-all">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                        <div class="flex gap-1 border-l border-slate-900/5 dark:border-white/5 pl-2">
                            <button onclick="editRFO(${i.id})" class="text-blue-500 hover:text-blue-700 p-1.5 transition-colors" title="Editar"><i class="fa-solid fa-pen text-xs"></i></button>
                            <button onclick="deleteRFO(${i.id})" class="text-red-500 hover:text-red-700 p-1.5 transition-colors" title="Excluir"><i class="fa-solid fa-trash text-xs"></i></button>
                        </div>
                    </div>
                </div>

                <!-- Sleek collapsible drawer details -->
                <div class="px-3.5 pb-3.5 pt-0 border-t border-slate-900/5 dark:border-white/5 bg-slate-50/30 dark:bg-white/10">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-2">
                        <div class="bg-white dark:bg-gray-800/40 p-2.5 rounded-lg border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Causa Raiz</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.root_cause || 'Nenhuma registrada'}</p>
                        </div>
                        <div class="bg-white dark:bg-gray-800/40 p-2.5 rounded-lg border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Ações para Solução</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.action || 'Nenhuma registrada'}</p>
                        </div>
                        <div class="bg-white dark:bg-gray-800/40 p-2.5 rounded-lg border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Observações Adicionais</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed">${i.observations || i.description || 'Nenhuma observação final'}</p>
                        </div>
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
            <div class="bg-white dark:bg-gray-900 rounded-2xl border border-slate-900/10 dark:border-white/10 p-4 shadow-sm hover:shadow-md hover:border-orange-500/20 dark:hover:border-orange-500/20 transition-all duration-300 flex flex-wrap md:flex-nowrap items-center justify-between gap-4 group relative overflow-hidden animate-premium">
                <!-- Left: Glowing Icon + Identity -->
                <div class="flex items-center gap-3.5 min-w-[240px] flex-1">
                    <div class="w-11 h-11 rounded-2xl bg-orange-50 dark:bg-orange-950/20 text-orange-500 flex items-center justify-center text-base shadow-inner shrink-0 group-hover:scale-105 transition-transform duration-300">
                        <i class="fa-solid fa-bolt"></i>
                    </div>
                    <div class="min-w-0">
                        <h4 class="font-extrabold text-slate-800 dark:text-white text-sm truncate leading-tight">${i.name}</h4>
                        <p class="text-[10px] text-slate-400 font-bold flex items-center gap-1 mt-1 leading-none"><i class="fa-solid fa-location-dot text-slate-300 dark:text-gray-600"></i> ${i.location}</p>
                    </div>
                </div>

                <!-- Middle 1: Fuel Tank Capacity & Slider -->
                <div class="flex flex-col min-w-[180px] md:w-64">
                    <div class="flex justify-between items-end mb-1.5 text-[10px] font-bold">
                        <span class="text-slate-400 uppercase tracking-widest">Combustível</span>
                        <span class="text-slate-700 dark:text-gray-300">${i.current_qty}L <span class="text-slate-400">/ ${i.capacity_total}L</span></span>
                    </div>
                    <div class="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex relative border border-slate-200/20">
                        <div class="h-full rounded-full transition-all duration-500 ${colorClass}" style="width: ${perc}%"></div>
                    </div>
                    <span class="text-[9px] font-black tracking-wider uppercase mt-1 ${perc < 25 ? 'text-red-500' : perc < 50 ? 'text-amber-500' : 'text-emerald-500'}">${perc}% de autonomia</span>
                </div>

                <!-- Middle 2: Reserve Liters & Cans -->
                <div class="bg-blue-50/45 dark:bg-blue-950/15 border border-blue-100 dark:border-blue-950/30 rounded-xl p-2.5 flex items-center gap-3 shrink-0 min-w-[150px]">
                    <div class="w-8 h-8 rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-500 flex items-center justify-center shrink-0">
                        <i class="fa-solid fa-fill-drip text-sm"></i>
                    </div>
                    <div>
                        <span class="text-[8px] font-black text-blue-400 dark:text-blue-500 uppercase tracking-wider block leading-none mb-0.5">Estoque Reserva</span>
                        <span class="text-xs font-bold text-blue-800 dark:text-blue-300 leading-tight">${i.reserve_cans || 0} <span class="text-[10px] font-normal text-blue-400">un.</span> | ${i.reserve_liters || 0}L</span>
                    </div>
                </div>

                <!-- Middle 3: Status & Fuel Type Badges -->
                <div class="flex flex-col items-start gap-1 shrink-0">
                    <span class="px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-wider shrink-0 ${i.status === 'OPERACIONAL' ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600' : 'bg-red-50 dark:bg-red-950/20 text-red-600'}">
                        ${i.status}
                    </span>
                    <span class="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded text-[8px] font-black uppercase tracking-wider shrink-0 mt-0.5">
                        ${i.fuel_type}
                    </span>
                </div>

                <!-- Right: Action Buttons -->
                <div class="flex items-center gap-2 shrink-0 ml-auto md:ml-0">
                    <button onclick="openAbastecer(${i.id})" class="px-3.5 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-orange-500/10 transition-all active:scale-95">
                        <i class="fa-solid fa-gas-pump"></i> Abastecer
                    </button>
                    <button onclick="editGerador(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-50 dark:hover:bg-white/5 rounded-xl transition-all" title="Editar">
                        <i class="fa-solid fa-pen text-[10px]"></i>
                    </button>
                    <button onclick="deleteGerador(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-red-100 text-red-400 hover:bg-red-50 rounded-xl transition-all" title="Excluir">
                        <i class="fa-solid fa-trash text-[10px]"></i>
                    </button>
                </div>
            </div>`;
        }).join('');
    } else if(slug === 'rota_exata') {
        rotaExataData = data;
        container.innerHTML = data.map(i => {
            const dateStr = i.date ? new Date(i.date + 'T00:00:00').toLocaleDateString() : '-';
            const techList = i.techs_data || [];
            
            return `
            <div class="bg-white dark:bg-gray-900 rounded-2xl border border-slate-900/10 dark:border-white/10 p-4 shadow-sm hover:shadow-md hover:border-purple-500/20 dark:hover:border-purple-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden animate-premium">
                <!-- Sleek horizontal row layout -->
                <div class="flex flex-wrap md:flex-nowrap items-center justify-between gap-4">
                    
                    <!-- Left: Icon + Main Info -->
                    <div class="flex items-center gap-3.5 min-w-[240px] flex-1">
                        <div class="w-11 h-11 rounded-2xl bg-purple-50 dark:bg-purple-950/20 text-purple-600 flex items-center justify-center text-base shadow-inner shrink-0 group-hover:scale-105 transition-transform duration-300">
                            <i class="fa-solid fa-route"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-2 mb-1">
                                <span class="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full text-[9px] font-black uppercase tracking-wider shrink-0">Rota Exata</span>
                                <span class="text-[10px] text-slate-400 font-bold shrink-0">${dateStr}</span>
                            </div>
                            <h4 class="font-extrabold text-slate-800 dark:text-white text-sm truncate leading-tight">${techList.length} Técnico(s) Supervisionado(s)</h4>
                            <p class="text-[9px] text-slate-400 font-black uppercase tracking-widest mt-1"><i class="fa-solid fa-user-shield text-purple-400 mr-1"></i> Supervisor: ${i.supervisor_name || 'N/A'}</p>
                        </div>
                    </div>

                    <!-- Center: Participant Badges -->
                    <div class="flex-1 min-w-[200px]">
                        <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1.5">Técnicos Auditados</span>
                        <div class="flex flex-wrap gap-1">
                            ${techList.map(t => `<span class="px-2.5 py-0.5 bg-slate-100 dark:bg-white/5 rounded-lg text-[10px] font-bold text-slate-600 dark:text-gray-300 border border-slate-200/20">${t.tech_name || 'N/A'}</span>`).join('')}
                        </div>
                    </div>

                    <!-- Right: Action Buttons + Collapse Trigger -->
                    <div class="flex items-center gap-2 shrink-0 ml-auto md:ml-0">
                        <button onclick="downloadRotaPDF(${i.id})" class="px-3 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-purple-500/10 transition-all active:scale-95" title="Baixar PDF">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                        <button onclick="editRota(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-50 dark:hover:bg-white/5 rounded-xl transition-all" title="Editar">
                            <i class="fa-solid fa-pen text-[10px]"></i>
                        </button>
                        <button onclick="deleteRota(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-red-100 text-red-400 hover:bg-red-50 rounded-xl transition-all" title="Excluir">
                            <i class="fa-solid fa-trash text-[10px]"></i>
                        </button>
                        <button onclick="const details = this.closest('.group').querySelector('.rota-expanded-row'); details.classList.toggle('hidden'); this.querySelector('i').classList.toggle('rotate-180')" class="w-8.5 h-8.5 flex items-center justify-center bg-slate-50 dark:bg-gray-800 text-slate-500 rounded-xl hover:bg-slate-100 dark:hover:bg-white/5 transition-all" title="Ver Detalhes">
                            <i class="fa-solid fa-chevron-down text-[10px] transition-transform duration-300"></i>
                        </button>
                    </div>
                </div>

                <!-- Collapsible Drawer Detail -->
                <div class="rota-expanded-row hidden border-t border-slate-900/5 dark:border-white/5 bg-slate-50/50 dark:bg-white/5 p-4 mt-3 space-y-3 rounded-xl">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-2">Detalhes dos Trajetos</span>
                            <div class="space-y-3">
                                ${techList.map((t, idx) => `
                                    <div class="border-l-2 border-purple-500 pl-3">
                                        <h5 class="text-xs font-bold text-slate-700 dark:text-gray-200">${t.tech_name || 'Técnico'}</h5>
                                        <p class="text-[10px] text-slate-500 mt-0.5">
                                            <strong>Rota Planejada:</strong> ${t.planned_route || 'N/A'} <br>
                                            <strong>Saída Pátio:</strong> ${t.yard_departure_time || 'N/A'} | 
                                            <strong>Almoço:</strong> ${t.lunch_start || 'N/A'} - ${t.lunch_end || 'N/A'}
                                        </p>
                                    </div>
                                `).join('')}
                            </div>
                        </div>

                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5 space-y-3">
                            <div>
                                <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-2">Atrasos & Desvios</span>
                                <div class="space-y-2">
                                    ${techList.map(t => {
                                        const delay = t.delay_reason ? `<span class="text-amber-500 font-bold">Atraso: ${t.delay_reason}</span>` : `<span class="text-emerald-500 font-bold">Sem Atraso</span>`;
                                        const dev = (t.route_deviation || t.identified_reason) ? `<span class="text-red-500 font-bold">Desvio: ${t.route_deviation || 'Local N/A'} (${t.identified_reason || 'Motivo N/A'})</span>` : `<span class="text-emerald-500 font-bold">Sem Desvio</span>`;
                                        return `
                                            <div class="text-[10px] text-slate-600 dark:text-gray-300 leading-tight">
                                                <strong>${t.tech_name || 'Técnico'}:</strong> ${delay} | ${dev}
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            </div>
                            
                            <div class="border-t border-slate-200/50 dark:border-white/5 pt-2">
                                <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Observações do Supervisor</span>
                                <p class="text-[10px] text-slate-600 dark:text-gray-300 leading-relaxed">${i.obs || 'Nenhuma observação geral registrada.'}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;
        }).join('');
    } else if(slug === 'supervisao') {
        supervisaoData = data;
        container.innerHTML = data.map(i => {
            const dateStr = i.date ? new Date(i.date + 'T00:00:00').toLocaleDateString() : '-';
            const techList = i.techs_data || [];
            
            return `
            <div class="bg-white dark:bg-gray-900 rounded-2xl border border-slate-900/10 dark:border-white/10 p-4 shadow-sm hover:shadow-md hover:border-emerald-500/20 dark:hover:border-emerald-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden animate-premium">
                <!-- Sleek horizontal row layout -->
                <div class="flex flex-wrap md:flex-nowrap items-center justify-between gap-4">
                    
                    <!-- Left: Icon + Main Info -->
                    <div class="flex items-center gap-3.5 min-w-[240px] flex-1">
                        <div class="w-11 h-11 rounded-2xl bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 flex items-center justify-center text-base shadow-inner shrink-0 group-hover:scale-105 transition-transform duration-300">
                            <i class="fa-solid fa-users-viewfinder"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-2 mb-1">
                                <span class="px-2 py-0.5 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 rounded-full text-[9px] font-black uppercase tracking-wider shrink-0">Supervisão Campo</span>
                                <span class="text-[10px] text-slate-400 font-bold shrink-0">${dateStr}</span>
                            </div>
                            <h4 class="font-extrabold text-slate-800 dark:text-white text-sm truncate leading-tight">${techList.length} Técnico(s) Supervisionado(s)</h4>
                            <p class="text-[9px] text-slate-400 font-black uppercase tracking-widest mt-1"><i class="fa-solid fa-user-shield text-emerald-400 mr-1"></i> Supervisor: ${i.supervisor_name || 'N/A'}</p>
                        </div>
                    </div>

                    <!-- Center: Participant Badges -->
                    <div class="flex-1 min-w-[200px]">
                        <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1.5">Técnicos Supervisionados</span>
                        <div class="flex flex-wrap gap-1">
                            ${techList.map(t => `<span class="px-2.5 py-0.5 bg-slate-100 dark:bg-white/5 rounded-lg text-[10px] font-bold text-slate-600 dark:text-gray-300 border border-slate-200/20">${t.tech_name || 'N/A'}</span>`).join('')}
                        </div>
                    </div>

                    <!-- Right: Action Buttons + Collapse Trigger -->
                    <div class="flex items-center gap-2 shrink-0 ml-auto md:ml-0">
                        <button onclick="downloadSupervisaoPDF(${i.id})" class="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-[10px] font-black uppercase tracking-wider flex items-center gap-1.5 shadow-md shadow-emerald-500/10 transition-all active:scale-95" title="Baixar PDF">
                            <i class="fa-solid fa-file-pdf"></i> PDF
                        </button>
                        <button onclick="editSupervisao(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-slate-200 dark:border-white/10 text-slate-500 hover:bg-slate-50 dark:hover:bg-white/5 rounded-xl transition-all" title="Editar">
                            <i class="fa-solid fa-pen text-[10px]"></i>
                        </button>
                        <button onclick="deleteSupervisao(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-red-100 text-red-400 hover:bg-red-50 rounded-xl transition-all" title="Excluir">
                            <i class="fa-solid fa-trash text-[10px]"></i>
                        </button>
                        <button onclick="const details = this.closest('.group').querySelector('.supervisao-expanded-row'); details.classList.toggle('hidden'); this.querySelector('i').classList.toggle('rotate-180')" class="w-8.5 h-8.5 flex items-center justify-center bg-slate-50 dark:bg-gray-800 text-slate-500 rounded-xl hover:bg-slate-100 dark:hover:bg-white/5 transition-all" title="Ver Detalhes">
                            <i class="fa-solid fa-chevron-down text-[10px] transition-transform duration-300"></i>
                        </button>
                    </div>
                </div>

                <!-- Collapsible Drawer Detail -->
                <div class="supervisao-expanded-row hidden border-t border-slate-900/5 dark:border-white/5 bg-slate-50/50 dark:bg-white/5 p-4 mt-3 space-y-3 rounded-xl">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-2">Detalhes das Auditorias</span>
                            <div class="space-y-3">
                                ${techList.map((t, idx) => `
                                    <div class="border-l-2 border-emerald-500 pl-3">
                                        <h5 class="text-xs font-bold text-slate-700 dark:text-gray-200">${t.tech_name || 'Técnico'}</h5>
                                        <p class="text-[10px] text-slate-500 mt-0.5">
                                            <strong>Local:</strong> ${t.location || 'N/A'} | <strong>Horário:</strong> ${t.supervision_time || 'N/A'} <br>
                                            <strong>Atividade:</strong> ${t.activity || 'N/A'} <br>
                                            <strong>Ação / Conclusão:</strong> ${t.conclusion || 'N/A'}
                                        </p>
                                    </div>
                                `).join('')}
                            </div>
                        </div>

                        <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5 space-y-3">
                            <div>
                                <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-2">Segurança (EPI/EPC) & Risco</span>
                                <div class="space-y-2">
                                    ${techList.map(t => {
                                        const epiStatus = t.epi === 'OK' ? `<span class="text-emerald-500 font-bold">EPI: OK</span>` : `<span class="text-red-500 font-bold">EPI: INCORRETO</span>`;
                                        const epcStatus = t.epc === 'OK' ? `<span class="text-emerald-500 font-bold">EPC: OK</span>` : `<span class="text-red-500 font-bold">EPC: INCORRETO</span>`;
                                        const ladder = t.ladder_position === 'OK' ? `<span class="text-emerald-500 font-bold">Escada: OK</span>` : `<span class="text-red-500 font-bold">Escada: INCORRETA</span>`;
                                        const car = t.car_position === 'OK' ? `<span class="text-emerald-500 font-bold">Carro: OK</span>` : `<span class="text-red-500 font-bold">Carro: INCORRETO</span>`;
                                        const uniform = t.uniform === 'OK' ? `<span class="text-emerald-500 font-bold">Uniforme: OK</span>` : `<span class="text-red-500 font-bold">Uniforme: INCORRETO</span>`;
                                        const risk = t.risk_level === 'Alto' ? `<span class="px-1.5 py-0.5 bg-red-100 text-red-600 rounded text-[9px] font-black">Risco Alto</span>` : t.risk_level === 'Médio' ? `<span class="px-1.5 py-0.5 bg-amber-100 text-amber-600 rounded text-[9px] font-black">Risco Médio</span>` : `<span class="px-1.5 py-0.5 bg-emerald-100 text-emerald-600 rounded text-[9px] font-black">Risco Baixo</span>`;
                                        
                                        return `
                                            <div class="text-[10px] text-slate-600 dark:text-gray-300 leading-normal border-b border-slate-100 dark:border-white/5 pb-1">
                                                <strong>${t.tech_name || 'Técnico'}:</strong> ${epiStatus} | ${epcStatus} | ${ladder} | ${car} | ${uniform} | ${risk}
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            </div>
                            
                            <div class="pt-1">
                                <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Observações do Supervisor</span>
                                <p class="text-[10px] text-slate-600 dark:text-gray-300 leading-relaxed">${i.obs || 'Nenhuma observação geral registrada.'}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;
        }).join('');
    } else if(slug === 'solicitacoes') {
        solicitacoesList = data;
        renderSolicitacoes(data);
    } else {
        container.innerHTML = `<p class="text-slate-400 text-sm italic">Dados carregados: ${data.length} itens.</p>`;
    }
}

function renderSolicitacoes(items) {
    const container = document.getElementById('list-solicitacoes');
    if (!container) return;
    
    if (!items || items.length === 0) {
        container.innerHTML = `
            <div class="p-8 text-center bg-slate-50 dark:bg-white/5 rounded-3xl border border-dashed border-slate-900/10 dark:border-white/10">
                <i class="fa-solid fa-folder-open text-slate-400 text-3xl mb-3"></i>
                <p class="text-sm text-slate-500 dark:text-gray-400 font-bold">Nenhuma solicitação encontrada.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = items.map(i => {
        let statusBadge = '';
        if(i.status === 'Aprovada') {
            statusBadge = '<span class="px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 shrink-0 border border-emerald-200/20"><i class="fa-solid fa-circle-check mr-1"></i>Aprovada</span>';
        } else if(i.status === 'Recusada') {
            statusBadge = '<span class="px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider bg-red-100 dark:bg-red-900/30 text-red-600 shrink-0 border border-red-200/20"><i class="fa-solid fa-circle-xmark mr-1"></i>Recusada</span>';
        } else {
            statusBadge = '<span class="px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-600 shrink-0 border border-amber-200/20"><i class="fa-solid fa-clock mr-1 animate-pulse"></i>Pendente</span>';
        }

        // Beautiful capsule config for each type
        let iIcon = 'fa-circle-info';
        let iBg = 'bg-slate-50 dark:bg-slate-900/50 text-slate-500';
        
        if (i.type === 'Troca de Plantão') {
            iIcon = 'fa-calendar-days';
            iBg = 'bg-blue-50 dark:bg-blue-950/20 text-blue-600';
        } else if (i.type === 'Folga / Compensação') {
            iIcon = 'fa-umbrella-beach';
            iBg = 'bg-teal-50 dark:bg-teal-950/20 text-teal-600';
        } else if (i.type === 'Feriado (Escala)') {
            iIcon = 'fa-business-time';
            iBg = 'bg-purple-50 dark:bg-purple-950/20 text-purple-600';
        } else if (i.type === 'Material / EPI') {
            iIcon = 'fa-helmet-safety';
            iBg = 'bg-amber-50 dark:bg-amber-950/20 text-amber-600';
        } else if (i.type === 'Adiantamento') {
            iIcon = 'fa-hand-holding-dollar';
            iBg = 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600';
        } else if (i.type === 'Afastamento / Médico') {
            iIcon = 'fa-truck-medical';
            iBg = 'bg-rose-50 dark:bg-rose-950/20 text-rose-600';
        }

        const dateStr = i.date ? new Date(i.date).toLocaleDateString() : '-';
        const timeStr = i.date ? new Date(i.date).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : '';

        return `
        <div class="bg-white dark:bg-gray-900 rounded-2xl border border-slate-900/10 dark:border-white/10 p-4 shadow-sm hover:shadow-md hover:border-indigo-500/20 dark:hover:border-indigo-500/20 transition-all duration-300 flex flex-col group relative overflow-hidden animate-premium">
            <!-- Row layout -->
            <div class="flex flex-wrap md:flex-nowrap items-center justify-between gap-4">
                
                <!-- Left: Category Icon + Request Type & Meta -->
                <div class="flex items-center gap-3.5 min-w-[240px] flex-1">
                    <div class="w-11 h-11 rounded-2xl flex items-center justify-center text-base shadow-inner shrink-0 group-hover:scale-105 transition-transform duration-300 ${iBg}">
                        <i class="fa-solid ${iIcon}"></i>
                    </div>
                    <div class="min-w-0">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2 py-0.5 bg-slate-100 dark:bg-white/5 rounded-md text-[9px] font-black uppercase tracking-wider shrink-0 text-slate-500 dark:text-gray-400">${i.type}</span>
                            <span class="text-[10px] text-slate-400 font-bold shrink-0">${dateStr} às ${timeStr}</span>
                        </div>
                        <h4 class="font-extrabold text-slate-800 dark:text-white text-sm truncate leading-tight">${i.description || 'Sem descrição'}</h4>
                        <p class="text-[9px] text-slate-400 font-black uppercase tracking-widest mt-1"><i class="fa-solid fa-user-circle mr-1"></i> Solicitante: ${i.user_name || 'N/A'}</p>
                    </div>
                </div>

                <!-- Center: Observations snippet or details -->
                <div class="flex-1 min-w-[180px] hidden sm:block">
                    <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Observações Adicionais</span>
                    <p class="text-xs text-slate-500 dark:text-gray-400 truncate font-medium">${i.obs || 'Nenhuma observação extra.'}</p>
                </div>

                <!-- Right: Status Pill & Actions -->
                <div class="flex items-center gap-2.5 shrink-0 ml-auto md:ml-0">
                    ${statusBadge}
                    
                    <div class="flex items-center gap-1.5 border-l border-slate-900/5 dark:border-white/5 pl-2.5">
                        ${(i.status === 'PENDENTE' && (user_role === 'admin' || user_role === 'supervisor')) ? `
                            <button onclick="respondSolicitacao(${i.id}, 'Aprovada')" class="px-2.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-[10px] font-black uppercase tracking-wider transition-all active:scale-95 shadow-md shadow-emerald-500/10">Aprovar</button>
                            <button onclick="respondSolicitacao(${i.id}, 'Recusada')" class="px-2.5 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-[10px] font-black uppercase tracking-wider transition-all active:scale-95 shadow-md shadow-red-500/10">Recusar</button>
                        ` : ''}
                        
                        <button onclick="deleteSolicitacao(${i.id})" class="w-8.5 h-8.5 flex items-center justify-center border border-red-100 text-red-400 hover:bg-red-50 rounded-xl transition-all" title="Excluir">
                            <i class="fa-solid fa-trash text-[10px]"></i>
                        </button>
                        
                        <button onclick="const details = this.closest('.group').querySelector('.solicitacao-expanded-row'); details.classList.toggle('hidden'); this.querySelector('i').classList.toggle('rotate-180')" class="w-8.5 h-8.5 flex items-center justify-center bg-slate-50 dark:bg-gray-800 text-slate-500 rounded-xl hover:bg-slate-100 dark:hover:bg-white/5 transition-all" title="Ver Detalhes">
                            <i class="fa-solid fa-chevron-down text-[10px] transition-transform duration-300"></i>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Collapsible Drawer Detail -->
            <div class="solicitacao-expanded-row hidden border-t border-slate-900/5 dark:border-white/5 bg-slate-50/50 dark:bg-white/5 p-4 mt-3 space-y-3 rounded-xl">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5">
                        <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Descrição Detalhada / Justificativa</span>
                        <blockquote class="text-xs text-slate-700 dark:text-gray-200 border-l-2 border-indigo-500 pl-3 py-1 font-medium bg-slate-50/50 dark:bg-white/5 rounded-r-lg italic">
                            "${i.description || 'Nenhuma descrição fornecida.'}"
                        </blockquote>
                        
                        <div class="mt-3">
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Observações Adicionais</span>
                            <p class="text-xs text-slate-600 dark:text-gray-300 leading-relaxed bg-slate-50/30 dark:bg-white/5 p-2 rounded-lg">${i.obs || 'Nenhuma observação informada.'}</p>
                        </div>
                    </div>

                    <div class="bg-white dark:bg-gray-800/40 p-3 rounded-xl border border-slate-900/5 dark:border-white/5 flex flex-col justify-between">
                        <div>
                            <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-2">Histórico de Decisão da Coordenação</span>
                            ${i.management_response ? `
                                <div class="p-3 bg-indigo-50/30 dark:bg-indigo-950/20 border border-indigo-200/50 dark:border-indigo-900/30 rounded-xl">
                                    <p class="text-[10px] font-black text-indigo-500 uppercase tracking-wider mb-1"><i class="fa-solid fa-user-tie mr-1"></i>Parecer da Gestão</p>
                                    <p class="text-xs text-slate-700 dark:text-gray-200 italic font-medium">"${i.management_response}"</p>
                                </div>
                            ` : `
                                <div class="p-3 bg-slate-50/50 dark:bg-white/5 rounded-xl border border-dashed border-slate-200 dark:border-white/5 text-center">
                                    <i class="fa-solid fa-clock-rotate-left text-slate-400 text-lg mb-1 block"></i>
                                    <p class="text-[10px] text-slate-400 font-bold">Esta solicitação ainda está sob análise.</p>
                                </div>
                            `}
                        </div>
                        
                        <div class="text-[9px] text-slate-400 font-bold uppercase tracking-wider border-t border-slate-900/5 dark:border-white/5 pt-2 mt-3 flex justify-between items-center">
                            <span>Status Atual: <strong class="${i.status === 'PENDENTE' ? 'text-amber-500' : i.status === 'Aprovada' ? 'text-emerald-500' : 'text-red-500'}">${i.status}</strong></span>
                            <span>Criado em: ${new Date(i.date).toLocaleString()}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');
}

function filterSolicitacoes(status) {
    currentSolicitacaoFilter = status;
    ['TODAS', 'PENDENTE', 'Aprovada', 'Recusada'].forEach(s => {
        const btn = document.getElementById(`filter-sol-${s}`);
        if (btn) {
            if (s === status) {
                btn.className = "px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition-all duration-300 bg-indigo-600 text-white shadow-md shadow-indigo-500/10";
            } else {
                btn.className = "px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition-all duration-300 text-slate-600 dark:text-gray-300 hover:bg-slate-200/50 dark:hover:bg-white/5";
            }
        }
    });
    
    if (status === 'TODAS') {
        renderSolicitacoes(solicitacoesList);
    } else {
        const filtered = solicitacoesList.filter(i => i.status === status);
        renderSolicitacoes(filtered);
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
    form.querySelector('[name="tech_responsible"]').value = item.tech || item.tech_responsible || '';
    form.querySelector('[name="observations"]').value = item.observations || item.description || '';
    
    // Render existing photos preview inside the modal
    const previewContainer = document.getElementById('rfo-photo-preview');
    if (previewContainer) {
        previewContainer.innerHTML = '';
        if (item.photos_json) {
            try {
                const photos = JSON.parse(item.photos_json);
                if (photos && photos.length > 0) {
                    previewContainer.innerHTML = photos.map(p => `
                        <div class="relative group rounded-xl overflow-hidden shadow-sm">
                            <img src="/static/vistorias_fotos/${p}" class="w-full h-16 object-cover border border-slate-900/10 dark:border-white/10">
                        </div>
                    `).join('');
                }
            } catch(e) {
                console.error("Erro ao fazer parse das fotos no modal:", e);
            }
        }
    }
    
    const submitBtn = document.querySelector('#modal-rfo button[onclick^="submitRFO"], #modal-rfo button[onclick^="saveEditRFO"]');
    submitBtn.onclick = () => saveEditRFO(id);
    submitBtn.innerHTML = '<i class="fa-solid fa-save"></i> Salvar Alterações';
    
    openModal('modal-rfo');
}

async function saveEditRFO(id) {
    const form = document.getElementById('form-rfo');
    const formData = new FormData(form);
    
    // Feedback visual
    const btn = document.querySelector('#modal-rfo button[onclick^="saveEditRFO"]');
    if(!btn) return;
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Salvando...';
    btn.disabled = true;
    
    try {
        const res = await fetch(`/api/gestao/rfo/${id}`, {
            method: 'PUT',
            body: formData
        });
        if (res.ok) {
            closeModal('modal-rfo');
            loadItems('rfo');
            form.reset();
            document.getElementById('rfo-photo-preview').innerHTML = "";
        } else {
            const errData = await res.json();
            alert("Erro ao editar RFO: " + (errData.error || "Verifique os dados e tente novamente."));
        }
    } catch(e) { 
        console.error(e); 
        alert("Erro de conexão ao salvar RFO.");
    } finally {
        btn.innerHTML = originalContent;
        btn.disabled = false;
    }
}

async function deleteRFO(id) {
    if(!confirm("Deseja realmente excluir este RFO?")) return;
    try {
        const res = await fetch(`/api/gestao/rfo/${id}`, { method: 'DELETE' });
        if(res.ok) loadItems('rfo');
    } catch(e) { console.error(e); }
}

function openModalSolicitacao() {
    const form = document.getElementById('form-solicitacao');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    openModal('modal-solicitacao');
}

async function submitSolicitacao() {
    const form = document.getElementById('form-solicitacao');
    form.requestSubmit();
}

async function deleteSolicitacao(id) {
    if(!confirm("Deseja realmente excluir esta solicitação?")) return;
    try {
        const res = await fetch(`/api/gestao/solicitacoes/${id}`, { method: 'DELETE' });
        if(res.ok) {
            loadItems('solicitacoes');
            showToast("Solicitação excluída.", "success");
        }
    } catch(e) { console.error(e); }
}

async function respondSolicitacao(id, status) {
    document.getElementById('respond-solicitacao-id').value = id;
    document.getElementById('respond-solicitacao-status').value = status;
    document.getElementById('respond-solicitacao-text').value = '';
    
    const titleEl = document.getElementById('respond-modal-title');
    const btnEl = document.getElementById('btn-submit-response');
    
    if (status === 'Aprovada') {
        titleEl.innerText = "Aprovar Solicitação";
        btnEl.className = "px-8 py-3 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-bold text-sm shadow-lg shadow-emerald-500/30 transition-all active:scale-95";
    } else {
        titleEl.innerText = "Recusar Solicitação";
        btnEl.className = "px-8 py-3 bg-red-600 hover:bg-red-700 text-white rounded-xl font-bold text-sm shadow-lg shadow-red-500/30 transition-all active:scale-95";
    }
    
    openModal('modal-respond-solicitacao');
}

async function submitResponseSolicitacao() {
    const id = document.getElementById('respond-solicitacao-id').value;
    const status = document.getElementById('respond-solicitacao-status').value;
    const response = document.getElementById('respond-solicitacao-text').value;
    
    if (!response) return showToast("Por favor, digite uma justificativa.", "error");

    try {
        const res = await fetch(`/api/gestao/solicitacoes/${id}/respond`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ status, response })
        });
        if(res.ok) {
            closeModal('modal-respond-solicitacao');
            loadItems('solicitacoes');
            showToast(`Solicitação ${status} com sucesso!`, "success");
        }
    } catch(e) { console.error(e); }
}

async function submitGerador() {
    const form = document.getElementById('form-gerador');
    form.requestSubmit();
}

function openModalGerador() {
    const form = document.getElementById('form-gerador');
    form.reset();
    if(form.querySelector('[name="id"]')) form.querySelector('[name="id"]').value = '';
    const btn = document.querySelector('#modal-gerador button[onclick="submitGerador()"]');
    if(btn) btn.innerText = "Salvar Gerador";
    openModal('modal-gerador');
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
    data.last_refill_date = new Date().toISOString().split('T')[0];
    
    try {
        const res = await fetch(`/api/gestao/geradores/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if(res.ok) {
            closeModal('modal-abastecer');
            loadItems('geradores');
            showToast('Abastecimento registrado com sucesso!', 'success');
        }
    } catch(e) { console.error(e); }
};

async function deleteGerador(id) {
    if(!confirm("Excluir este gerador?")) return;
    const res = await fetch(`/api/gestao/geradores/${id}`, { method: 'DELETE' });
    if(res.ok) {
        loadItems('geradores');
        showToast('Gerador excluído!', 'success');
    }
}

async function editGerador(id) {
    const item = currentGenerators.find(g => g.id === id);
    if(!item) return;
    const form = document.getElementById('form-gerador');
    if(form.querySelector('[name="id"]')) form.querySelector('[name="id"]').value = item.id;
    form.querySelector('[name="name"]').value = item.name;
    form.querySelector('[name="location"]').value = item.location;
    form.querySelector('[name="capacity_total"]').value = item.capacity_total;
    form.querySelector('[name="current_qty"]').value = item.current_qty;
    form.querySelector('[name="fuel_type"]').value = item.fuel_type;
    form.querySelector('[name="reserve_cans"]').value = item.reserve_cans;
    form.querySelector('[name="reserve_liters"]').value = item.reserve_liters;
    
    const btn = document.querySelector('#modal-gerador button[onclick="submitGerador()"]');
    if(btn) btn.innerText = "Salvar Alterações";
    
    openModal('modal-gerador');
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
    if(form.querySelector('[name="leader_id"]')) {
        form.querySelector('[name="leader_id"]').value = e.leader_id || '';
    }
    
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
        container.innerHTML = globalEquipes.map(e => {
            const leaderBadge = e.leader_name
                ? `<div class="inline-flex items-center gap-1.5 px-2.5 py-1 bg-amber-500/10 dark:bg-amber-500/5 border border-amber-500/20 rounded-xl text-[10px] text-amber-600 dark:text-amber-400 font-bold mb-3">
                       <i class="fa-solid fa-crown text-[9px]"></i>
                       <span>Líder: ${e.leader_name}</span>
                   </div>`
                : `<div class="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-white/5 border border-slate-900/5 dark:border-white/5 rounded-xl text-[10px] text-slate-500 dark:text-slate-400 font-semibold mb-3">
                       <i class="fa-solid fa-user-slash text-[9px]"></i>
                       <span>Sem Líder</span>
                   </div>`;

            return `
                <div class="bg-white/70 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-2xl p-5 shadow-sm group hover:shadow-md transition-all relative overflow-hidden">
                    <div class="absolute top-0 left-0 w-1.5 h-full" style="background-color: ${e.color}"></div>
                    <div class="flex justify-between items-start mb-2">
                        <div class="flex items-center gap-3">
                            <div class="w-3 h-3 rounded-full" style="background-color: ${e.color}"></div>
                            <h3 class="font-bold text-slate-800 dark:text-white">${e.name}</h3>
                        </div>
                        <div class="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button onclick="editEquipe(${e.id})" class="text-blue-500 hover:text-blue-700"><i class="fa-solid fa-pen-to-square"></i></button>
                            <button onclick="deleteEquipe(${e.id})" class="text-red-500 hover:text-red-700"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                    
                    ${leaderBadge}

                    <div class="space-y-2">
                        <p class="text-[10px] uppercase font-bold text-slate-400 tracking-widest">Membros (${e.members.length})</p>
                        <div class="flex flex-wrap gap-1">
                            ${e.members.map(m => {
                                const isLeader = e.leader_id === m.id;
                                return `
                                    <span class="px-2 py-0.5 ${isLeader ? 'bg-amber-500/15 border border-amber-500/35 text-amber-600 dark:text-amber-400 font-extrabold' : 'bg-slate-100 dark:bg-white/5 text-slate-600 dark:text-gray-300 font-bold'} rounded-full text-[10px] flex items-center gap-1">
                                        ${isLeader ? '<i class="fa-solid fa-crown text-[8px]"></i>' : ''}
                                        ${m.username}
                                    </span>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    // 2. Atualiza lista de rotatividade (Aba Escalas)
    const rotList = document.getElementById('rotation-teams-list');
    if(rotList) {
        rotList.innerHTML = globalEquipes.map(e => `
            <label class="flex flex-col items-center gap-3 p-4 bg-white/50 dark:bg-white/5 border border-slate-900/10 dark:border-white/10 rounded-2xl cursor-pointer hover:bg-purple-50 dark:hover:bg-purple-900/10 transition-all group">
                <input aria-label="input" type="checkbox" class="hidden peer" onchange="toggleRotationTeam(${e.id}, this)">
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
    
    const techIds = item.participants ? item.participants.split(',') : [];
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

async function loadHelperFeriados() {
    const container = document.getElementById('escala-helper-feriados');
    if(!container) return;
    try {
        const res = await fetch(`/api/gestao/proximos_feriados?t=${Date.now()}`);
        if(res.ok) {
            const data = await res.json();
            if(data.length > 0) {
                container.innerHTML = data.map(f => `
                    <button type="button" onclick="quickFillEscalaHoliday('${f.date}', '${f.name}')" 
                        class="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 hover:border-rose-500/30 text-rose-600 dark:text-rose-400 rounded-lg text-[10px] font-bold transition-all flex flex-col items-start gap-0.5 whitespace-nowrap flex-shrink-0">
                        <span class="font-extrabold flex items-center gap-1">
                            <i class="fa-solid fa-gift text-[9px]"></i> ${f.display_date} - ${f.name}
                        </span>
                        <span class="text-[8px] text-slate-400 font-semibold">${f.day_name}</span>
                    </button>
                `).join('');
            } else {
                container.innerHTML = `<span class="text-[10px] text-slate-400 p-1">Nenhum feriado próximo.</span>`;
            }
        } else {
            container.innerHTML = `<span class="text-[10px] text-red-400 p-1">Erro ao carregar feriados.</span>`;
        }
    } catch(err) {
        container.innerHTML = `<span class="text-[10px] text-red-400 p-1">Erro ao carregar feriados.</span>`;
    }
}

function quickFillEscalaHoliday(dateStr, holidayName) {
    const form = document.getElementById('form-escala');
    if(!form) return;
    form.querySelector('[name="date"]').value = dateStr;
    form.querySelector('[name="type"]').value = 'feriado';
    form.querySelector('[name="obs"]').value = `Plantão Especial - Feriado: ${holidayName}`;
    
    showToast(`Preenchido: ${holidayName} (${new Date(dateStr + 'T00:00:00').toLocaleDateString()})`, "success");
    
    ['[name="date"]', '[name="type"]', '[name="obs"]'].forEach(sel => {
        const el = form.querySelector(sel);
        if(el) {
            el.classList.add('ring-2', 'ring-purple-500');
            setTimeout(() => el.classList.remove('ring-2', 'ring-purple-500'), 1500);
        }
    });
}

function openModalEscala() {
    const form = document.getElementById('form-escala');
    form.reset();
    form.querySelector('[name="id"]').value = '';
    document.getElementById('escala-teams-display').innerHTML = 'Nenhuma equipe selecionada';
    document.getElementById('escala-team-ids').value = '';
    loadHelperFeriados();
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
    loadHelperFeriados();
    openModal('modal-escala');
}

async function deleteEscala(id) {
    if(!confirm("Deseja excluir esta escala manual?")) return;
    const res = await fetch(`/api/gestao/escalas/${id}`, { method: 'DELETE' });
    if(res.ok) loadItems('escalas');
}

async function showEscalaDetalhes(id) {
    const res = await fetch(`/api/gestao/escalas?view=list&t=${Date.now()}`);
    if(!res.ok) return alert("Erro ao carregar dados do plantão.");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return alert("Plantão não encontrado.");

    const tipoEl = document.getElementById('detalhe-escala-tipo');
    tipoEl.textContent = item.type;
    tipoEl.className = 'px-2.5 py-1 rounded-lg text-[10px] font-black uppercase tracking-wider ';
    if (item.type === 'sabado') {
        tipoEl.classList.add('bg-emerald-100', 'text-emerald-700', 'dark:bg-emerald-900/30', 'dark:text-emerald-400');
    } else if (item.type === 'domingo') {
        tipoEl.classList.add('bg-indigo-100', 'text-indigo-700', 'dark:bg-indigo-900/30', 'dark:text-indigo-400');
    } else {
        tipoEl.classList.add('bg-amber-100', 'text-amber-700', 'dark:bg-amber-900/30', 'dark:text-amber-400');
    }

    document.getElementById('detalhe-escala-data').textContent = new Date(item.date + 'T00:00:00').toLocaleDateString();

    const equipesEl = document.getElementById('detalhe-escala-equipes');
    equipesEl.innerHTML = '';
    if (item.team_ids) {
        const ids = item.team_ids.split(',').map(x => parseInt(x));
        const matched = globalEquipes.filter(e => ids.includes(e.id));
        if (matched.length > 0) {
            equipesEl.innerHTML = matched.map(e => `
                <span class="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded-md text-[10px] font-bold">
                    <i class="fa-solid fa-users text-[9px] mr-1"></i> ${e.name}
                </span>
            `).join('');
        } else {
            equipesEl.innerHTML = '<span class="text-slate-400 text-xs italic">Sem equipe vinculada</span>';
        }
    } else {
        equipesEl.innerHTML = '<span class="text-slate-400 text-xs italic">Sem equipe vinculada</span>';
    }

    const tecnicosEl = document.getElementById('detalhe-escala-tecnicos');
    tecnicosEl.innerHTML = '';
    if (item.technician_names) {
        const names = item.technician_names.split(',').map(x => x.trim());
        tecnicosEl.innerHTML = names.map(name => `
            <span class="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-md text-[10px] font-bold">
                <i class="fa-solid fa-user-gear text-[9px] mr-1"></i> ${name}
            </span>
        `).join('');
    } else {
        tecnicosEl.innerHTML = '<span class="text-slate-400 text-xs italic">Nenhum técnico escalado</span>';
    }

    document.getElementById('detalhe-escala-obs').textContent = item.obs || 'Nenhuma observação registrada para este plantão.';

    openModal('modal-escala-detalhes');
}

async function showReuniaoDetalhes(id) {
    const res = await fetch(`/api/gestao/reunioes?t=${Date.now()}`);
    if(!res.ok) return alert("Erro ao carregar dados da reunião.");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return alert("Reunião não encontrada.");

    document.getElementById('detalhe-reuniao-titulo').textContent = item.title;
    document.getElementById('detalhe-reuniao-assunto').textContent = item.subject;

    // Status badge
    const isCompleted = item.status === 'Concluída';
    const statusEl = document.getElementById('detalhe-reuniao-status');
    statusEl.innerHTML = `
        <span class="w-1.5 h-1.5 rounded-full ${isCompleted ? 'bg-emerald-500' : 'bg-purple-500 animate-pulse'}"></span>
        ${item.status}
    `;
    statusEl.className = `px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-wider flex items-center gap-1.5 ${
        isCompleted 
            ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400' 
            : 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400'
    }`;

    // Format dates
    let dateFormatted = 'N/A';
    if (item.date) {
        const dateParts = item.date.split('-');
        if (dateParts.length === 3) {
            dateFormatted = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
        }
    }
    document.getElementById('detalhe-reuniao-data').textContent = `${dateFormatted} às ${item.time}`;
    document.getElementById('detalhe-reuniao-local').textContent = item.location || 'Não especificado';
    document.getElementById('detalhe-reuniao-local').title = item.location || 'Não especificado';
    document.getElementById('detalhe-reuniao-responsavel').textContent = item.responsible || 'Não especificado';

    // Objective
    const objContainer = document.getElementById('detalhe-reuniao-objetivo-container');
    if (item.objective) {
        document.getElementById('detalhe-reuniao-objetivo').textContent = item.objective;
        objContainer.classList.remove('hidden');
    } else {
        objContainer.classList.add('hidden');
    }

    // Summary
    const sumContainer = document.getElementById('detalhe-reuniao-resumo-container');
    if (item.summary) {
        document.getElementById('detalhe-reuniao-resumo').textContent = item.summary;
        sumContainer.classList.remove('hidden');
    } else {
        sumContainer.classList.add('hidden');
    }

    // Actions
    const acContainer = document.getElementById('detalhe-reuniao-acoes-container');
    const acEl = document.getElementById('detalhe-reuniao-acoes');
    acEl.innerHTML = '';
    if (item.actions) {
        const lines = item.actions.split('\n').filter(x => x.trim());
        if (lines.length > 0) {
            acEl.innerHTML = lines.map(line => `
                <div class="flex items-start gap-1.5 text-xs text-slate-600 dark:text-gray-300">
                    <i class="fa-solid fa-square-check text-amber-500 mt-0.5 text-[10px]"></i>
                    <span>${line}</span>
                </div>
            `).join('');
            acContainer.classList.remove('hidden');
        } else {
            acContainer.classList.add('hidden');
        }
    } else {
        acContainer.classList.add('hidden');
    }

    // Participants
    const partContainer = document.getElementById('detalhe-reuniao-participantes-container');
    const partEl = document.getElementById('detalhe-reuniao-participantes');
    partEl.innerHTML = '';
    if (item.participant_names) {
        const names = item.participant_names.split(',').filter(x => x.trim());
        if (names.length > 0) {
            partEl.innerHTML = names.map(name => `
                <span class="px-2 py-0.5 bg-blue-50 dark:bg-blue-950/20 text-blue-600 dark:text-blue-400 rounded-md text-[10px] font-medium flex items-center gap-1">
                    <i class="fa-solid fa-user text-[8px]"></i> ${name.trim()}
                </span>
            `).join('');
            partContainer.classList.remove('hidden');
        } else {
            partContainer.classList.add('hidden');
        }
    } else {
        partContainer.classList.add('hidden');
    }

    openModal('modal-reuniao-detalhes');
}

async function showAnotacaoDetalhes(id) {
    const res = await fetch(`/api/gestao/anotacoes?t=${Date.now()}`);
    if(!res.ok) return alert("Erro ao carregar dados da anotação.");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return alert("Anotação não encontrada.");

    document.getElementById('detalhe-anotacao-titulo').textContent = item.title || 'Sem Título';
    document.getElementById('detalhe-anotacao-categoria').textContent = item.category || 'Geral';
    
    let dateFormatted = 'N/A';
    if (item.event_date) {
        const dateParts = item.event_date.split('-');
        if (dateParts.length === 3) {
            dateFormatted = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
        }
    }
    document.getElementById('detalhe-anotacao-data').textContent = dateFormatted;
    document.getElementById('detalhe-anotacao-descricao').textContent = item.description || '';

    openModal('modal-anotacao-detalhes');
}

async function showTarefaDetalhes(id) {
    const res = await fetch(`/api/gestao/tarefas?t=${Date.now()}`);
    if(!res.ok) return alert("Erro ao carregar dados da tarefa.");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return alert("Tarefa não encontrada.");

    document.getElementById('detalhe-tarefa-titulo').textContent = item.title || 'Sem Título';
    
    // Priority badge
    const pEl = document.getElementById('detalhe-tarefa-prioridade');
    pEl.textContent = item.priority || 'Média';
    let priorityColor = 'text-slate-600 bg-slate-100 dark:bg-slate-900/50';
    if(item.priority === 'Alta') priorityColor = 'text-orange-600 bg-orange-100 dark:bg-orange-950/20';
    else if(item.priority === 'Crítica') priorityColor = 'text-red-600 bg-red-100 dark:bg-red-950/20 animate-pulse';
    else if(item.priority === 'Baixa') priorityColor = 'text-blue-600 bg-blue-100 dark:bg-blue-950/20';
    pEl.className = `px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider ${priorityColor}`;

    // Status badge
    const sEl = document.getElementById('detalhe-tarefa-status');
    sEl.textContent = item.status || 'Pendente';
    let statusColor = 'text-slate-600 bg-slate-100 dark:bg-slate-900/50';
    if(item.status === 'Em Andamento') statusColor = 'text-indigo-600 bg-indigo-100 dark:bg-indigo-950/20';
    else if(item.status === 'Concluída') statusColor = 'text-emerald-600 bg-emerald-100 dark:bg-emerald-950/20';
    sEl.className = `px-2 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider ${statusColor}`;

    // Date
    let dateFormatted = 'Sem Prazo';
    if (item.deadline) {
        const dateParts = item.deadline.split('-');
        if (dateParts.length === 3) {
            dateFormatted = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
        }
    }
    document.getElementById('detalhe-tarefa-data').textContent = dateFormatted;
    document.getElementById('detalhe-tarefa-responsavel').textContent = item.responsible_name || 'Sem responsável';
    document.getElementById('detalhe-tarefa-descricao').textContent = item.description || 'Sem descrição';

    // Observations display
    const obsContainer = document.getElementById('detalhe-tarefa-obs-container');
    const obsEl = document.getElementById('detalhe-tarefa-obs');
    if (item.obs) {
        obsEl.textContent = item.obs;
        obsContainer.classList.remove('hidden');
    } else {
        obsContainer.classList.add('hidden');
    }

    openModal('modal-tarefa-detalhes');
}

async function showAtividadeRealizadaDetalhes(id) {
    const res = await fetch(`/api/gestao/atividades-realizadas?t=${Date.now()}`);
    if(!res.ok) return showToast("Erro ao carregar dados da atividade.", "error");
    const items = await res.json();
    const item = items.find(x => parseInt(x.id) === parseInt(id));
    if(!item) return showToast("Atividade não encontrada.", "error");

    document.getElementById('detalhe-atividade-titulo').textContent = item.title || 'Sem Título';
    document.getElementById('detalhe-atividade-responsavel').textContent = item.responsible_name || 'Sem responsável';
    
    let dateFormatted = 'N/D';
    if (item.date) {
        const dateParts = item.date.split('-');
        if (dateParts.length === 3) {
            dateFormatted = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
        }
    }
    document.getElementById('detalhe-atividade-data').textContent = dateFormatted;

    // Campos dinâmicos (Option B: blocks individuais)
    const camposContainer = document.getElementById('detalhe-atividade-campos-container');
    camposContainer.innerHTML = '';
    
    if (item.fields && item.fields.length > 0) {
        item.fields.forEach(f => {
            const block = document.createElement('div');
            block.className = "space-y-1 bg-slate-50 dark:bg-gray-800/40 p-4 rounded-xl border border-slate-900/5 dark:border-white/5";
            block.innerHTML = `
                <span class="text-[9px] font-bold text-slate-400 block uppercase tracking-wider">${f.label}</span>
                <p class="text-slate-600 dark:text-gray-300 text-xs leading-relaxed whitespace-pre-wrap">${f.value || '—'}</p>
            `;
            camposContainer.appendChild(block);
        });
    } else {
        camposContainer.innerHTML = '<p class="text-xs italic text-slate-400">Nenhum campo registrado</p>';
    }

    // Observações
    const obsContainer = document.getElementById('detalhe-atividade-obs-container');
    const obsEl = document.getElementById('detalhe-atividade-obs');
    if (item.obs) {
        obsEl.textContent = item.obs;
        obsContainer.classList.remove('hidden');
    } else {
        obsContainer.classList.add('hidden');
    }

    openModal('modal-atividade-realizada-detalhes');
}

function switchSubTab(subTabId) {
    document.getElementById('subpane-tarefas').classList.add('hidden');
    document.getElementById('subpane-atividades-realizadas').classList.add('hidden');
    
    const btnTarefas = document.getElementById('btnSubTabTarefas');
    const btnAtividades = document.getElementById('btnSubTabAtividadesRealizadas');
    
    btnTarefas.className = "flex-1 py-1.5 px-3 rounded-xl font-black text-[9px] uppercase tracking-widest transition-all duration-300 flex items-center justify-center gap-1.5 h-full active:scale-95 text-slate-400 dark:text-slate-400 hover:text-slate-600 dark:hover:text-slate-200";
    btnAtividades.className = "flex-1 py-1.5 px-3 rounded-xl font-black text-[9px] uppercase tracking-widest transition-all duration-300 flex items-center justify-center gap-1.5 h-full active:scale-95 text-slate-400 dark:text-slate-400 hover:text-slate-600 dark:hover:text-slate-200";

    const badgeTarefas = document.getElementById('badgeSubTabTarefas');
    const badgeAtividades = document.getElementById('badgeSubTabAtividades');
    
    badgeTarefas.className = "px-1.5 py-0.5 rounded text-[8px] font-black bg-slate-900/5 dark:bg-white/5 text-slate-400 dark:text-slate-400";
    badgeAtividades.className = "px-1.5 py-0.5 rounded text-[8px] font-black bg-slate-900/5 dark:bg-white/5 text-slate-400 dark:text-slate-400";

    if (subTabId === 'tarefas') {
        document.getElementById('subpane-tarefas').classList.remove('hidden');
        btnTarefas.className = "flex-1 py-1.5 px-3 rounded-xl font-black text-[9px] uppercase tracking-widest transition-all duration-300 flex items-center justify-center gap-1.5 h-full active:scale-95 bg-indigo-600 text-white shadow-md shadow-indigo-500/25";
        badgeTarefas.className = "px-1.5 py-0.5 rounded text-[8px] font-black bg-white/20 text-white";
        
        document.getElementById('btn-header-nova-tarefa').classList.remove('hidden');
        document.getElementById('btn-header-nova-atividade').classList.add('hidden');
    } else {
        document.getElementById('subpane-atividades-realizadas').classList.remove('hidden');
        btnAtividades.className = "flex-1 py-1.5 px-3 rounded-xl font-black text-[9px] uppercase tracking-widest transition-all duration-300 flex items-center justify-center gap-1.5 h-full active:scale-95 bg-emerald-600 text-white shadow-md shadow-emerald-500/25";
        badgeAtividades.className = "px-1.5 py-0.5 rounded text-[8px] font-black bg-white/20 text-white";
        
        document.getElementById('btn-header-nova-tarefa').classList.add('hidden');
        document.getElementById('btn-header-nova-atividade').classList.remove('hidden');
    }
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
        if(formId === 'form-escala') {
            data.technician_ids = Array.from(e.target.querySelectorAll('input[name="user_ids"]:checked')).map(i => i.value);
        }
        if(formId === 'form-tarefa') {
            data.show_on_calendar = document.getElementById('task_show_on_calendar').checked;
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
            const props = info.event.extendedProps || {};
            if(info.event.id && info.event.id.startsWith('m_')) {
                const scaleId = info.event.id.replace('m_', '');
                if (props.scale_type === 'domingo' || props.scale_type === 'feriado') {
                    showEscalaDetalhes(scaleId);
                } else {
                    editEscala(scaleId);
                }
            } else if(info.event.id && info.event.id.startsWith('r_')) {
                const meetingId = info.event.id.replace('r_', '');
                showReuniaoDetalhes(parseInt(meetingId));
            } else if(info.event.id && info.event.id.startsWith('a_')) {
                const noteId = info.event.id.replace('a_', '');
                showAnotacaoDetalhes(parseInt(noteId));
            } else if(info.event.id && info.event.id.startsWith('t_')) {
                const taskId = info.event.id.replace('t_', '');
                showTarefaDetalhes(parseInt(taskId));
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
    
    const options = globalTecnicos.map(t => `<option value="${t.username}">${t.username}</option>`).join('');
    
    block.innerHTML = `
        <button type="button" onclick="this.parentElement.remove()" class="btn-remove-block absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full text-slate-400 hover:bg-red-50 hover:text-red-500 transition-all">
            <i class="fa-solid fa-trash"></i>
        </button>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Técnico Responsável</label>
                <select name="tech_responsible" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white outline-none">
                    <option value="" disabled selected>Selecione o técnico</option>
                    ${options}
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Cliente</label>
                <input id="client_name" type="text" name="client_name" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Código Cliente</label>
                <input id="client_code" type="text" name="client_code" class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Atividade Realizada</label>
                <input id="type" type="text" name="type" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none" placeholder="Ex: Fusão de Fibra">
            </div>
            <div>
                <label class="block text-[10px] font-bold text-slate-400 uppercase mb-1">Horário da Visita</label>
                <input id="time" type="time" name="time" required class="w-full bg-white dark:bg-gray-900 border border-slate-900/10 dark:border-white/10 rounded-xl px-4 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500/20 outline-none">
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
    
    const blocks = item.blocks && item.blocks.length > 0 ? item.blocks : [{
        tech_responsible: item.tech_responsible || item.tech || '',
        client_name: item.client_name || '',
        client_code: item.client_code || '',
        type: item.type || '',
        time: item.time || '',
        quality_rating: item.quality || 'Excelente',
        os_closure: item.os_closure || 'Sim',
        client_feedback: item.feedback || '',
        conclusion: item.conclusion || ''
    }];
    
    blocks.forEach((b, idx) => {
        addVistoriaBlock();
        const block = document.getElementById('vistoria-blocks').children[idx];
        
        block.querySelector('select[name="tech_responsible"]').value = b.tech_responsible || '';
        block.querySelector('input[name="client_name"]').value = b.client_name || '';
        block.querySelector('input[name="client_code"]').value = b.client_code || '';
        block.querySelector('input[name="type"]').value = b.type || '';
        block.querySelector('input[name="time"]').value = b.time || '';
        block.querySelector('select[name="quality_rating"]').value = b.quality_rating || 'Excelente';
        block.querySelector('select[name="os_closure"]').value = b.os_closure || 'Sim';
        block.querySelector('textarea[name="client_feedback"]').value = b.client_feedback || '';
        block.querySelector('textarea[name="conclusion"]').value = b.conclusion || '';
        
        // Se houver apenas 1 bloco, esconde o botão de remover
        if (blocks.length === 1) {
            block.querySelector('.btn-remove-block').classList.add('hidden');
        }
    });
    
    const submitBtn = document.getElementById('btn-save-vistoria');
    submitBtn.onclick = () => saveEditAtividade(id);
    submitBtn.innerHTML = '<i class="fa-solid fa-save"></i> Salvar Alteração';
    
    // Permite adicionar mais blocos/técnicos na edição
    document.querySelector('#modal-vistoria button[onclick="addVistoriaBlock()"]').classList.remove('hidden');
    openModal('modal-vistoria');
}

async function saveEditAtividade(id) {
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
        const res = await fetch(`/api/gestao/atividades/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        if(res.ok) {
            closeModal('modal-vistoria');
            loadItems('atividades');
        } else {
            alert("Erro ao salvar alterações da vistoria.");
        }
    } catch(e) { 
        console.error(e); 
        alert("Erro de conexão.");
    }
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
const tecnicos_js = [];
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
                <input id="supervision_date" type="date" name="supervision_date" value="${data ? data.supervision_date : today}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Saída Pátio</label>
                <input id="yard_departure_time" type="time" name="yard_departure_time" value="${data ? data.yard_departure_time || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Almoço (Início / Fim)</label>
                <div class="flex items-center gap-2">
                    <input id="lunch_start" type="time" name="lunch_start" value="${data ? data.lunch_start || '' : ''}" class="flex-1 bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-4 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
                    <input id="lunch_end" type="time" name="lunch_end" value="${data ? data.lunch_end || '' : ''}" class="flex-1 bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-4 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all">
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            <div class="bg-slate-50/50 dark:bg-white/5 p-6 rounded-[2rem] border border-slate-900/5 dark:border-white/5">
                <div class="flex items-center justify-between mb-4">
                    <span class="text-xs font-black text-slate-500 dark:text-gray-400 uppercase tracking-widest">Atraso na Saída?</span>
                    <label class="relative inline-flex items-center cursor-pointer">
                        <input id="has_delay" type="checkbox" name="has_delay" class="sr-only peer" ${data && data.delay_reason ? 'checked' : ''} onchange="toggleRotaField('${rowId}-delay', this.checked)">
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
                        <input id="has_deviation" type="checkbox" name="has_deviation" class="sr-only peer" ${data && (data.route_deviation || data.identified_reason) ? 'checked' : ''} onchange="toggleRotaField('${rowId}-deviation', this.checked)">
                        <div class="w-11 h-6 bg-slate-200 peer-focus:outline-none rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:width-5 after:transition-all dark:border-gray-600 peer-checked:bg-red-500"></div>
                    </label>
                </div>
                <div id="${rowId}-deviation" class="${data && (data.route_deviation || data.identified_reason) ? '' : 'hidden'} space-y-4 animate-premium">
                    <input id="route_deviation" type="text" name="route_deviation" value="${data ? data.route_deviation || '' : ''}" class="w-full bg-white dark:bg-slate-900/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-red-500/10 transition-all" placeholder="Local do desvio">
                    <textarea name="identified_reason" rows="2" class="w-full bg-white dark:bg-slate-900/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-red-500/10 transition-all resize-none" placeholder="Motivo identificado">${data ? data.identified_reason || '' : ''}</textarea>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Rota Planejada</label>
                <input id="planned_route" type="text" name="planned_route" value="${data ? data.planned_route || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all" placeholder="Ex: Zona Norte - Equipe Alfa">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Observações Adicionais</label>
                <input id="observations" type="text" name="observations" value="${data ? data.observations || '' : ''}" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-purple-500/10 transition-all" placeholder="Algum outro detalhe importante...">
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
    console.log('[Supervisao] openModalSupervisao() called with id:', id);
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
    console.log('[Supervisao] addSupervisaoRow() called');
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
                <input id="location" type="text" name="location" value="${data ? data.location || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all" placeholder="Rua, Bairro, N°">
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Horário</label>
                <input id="supervision_time" type="time" name="supervision_time" value="${data ? data.supervision_time || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all">
            </div>
            <div class="md:col-span-2 lg:col-span-3">
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Atividade Observada</label>
                <input id="activity" type="text" name="activity" value="${data ? data.activity || '' : ''}" required class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all" placeholder="O que o técnico estava fazendo?">
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
                                <input id="fieldid-rowId" type="radio" name="${field.id}-${rowId}" value="OK" ${(!data || data[field.id] === 'OK') ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-emerald-500 peer-checked:border-emerald-500 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">OK</div>
                            </label>
                            <label class="flex-1 md:flex-none">
                                <input id="fieldid-rowId" type="radio" name="${field.id}-${rowId}" value="IRR" ${data && data[field.id] === 'IRR' ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-red-500 peer-checked:border-red-500 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">NÃO OK</div>
                            </label>
                            <label class="flex-1 md:flex-none">
                                <input id="fieldid-rowId" type="radio" name="${field.id}-${rowId}" value="NA" ${data && data[field.id] === 'NA' ? 'checked' : ''} class="peer hidden">
                                <div class="px-6 py-2.5 rounded-xl border-2 border-slate-200 dark:border-white/5 text-center transition-all cursor-pointer peer-checked:bg-slate-400 peer-checked:border-slate-400 peer-checked:text-white text-slate-400 font-black text-[10px] uppercase">N/A</div>
                            </label>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Grau de Risco Observado</label>
                <select name="risk_level" class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-bold text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all">
                    <option value="Baixo" ${data && data.risk_level === 'Baixo' ? 'selected' : ''}>Baixo (Conforme)</option>
                    <option value="Médio" ${data && data.risk_level === 'Médio' ? 'selected' : ''}>Médio (Requer Atenção)</option>
                    <option value="Alto" ${data && data.risk_level === 'Alto' ? 'selected' : ''}>Alto (Intervenção Imediata)</option>
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Conclusão e Recomendações</label>
                <textarea name="conclusion" required placeholder="Observações finais para este técnico..." class="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-900/5 dark:border-white/5 rounded-2xl px-5 py-4 text-sm font-medium text-slate-900 dark:text-white outline-none focus:ring-4 focus:ring-emerald-500/10 transition-all h-20 resize-none">${data ? data.conclusion || '' : ''}</textarea>
            </div>
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
            uniform: row.querySelector(`[name="uniform-${rowId}"]:checked`)?.value || 'OK',
            risk_level: row.querySelector('[name="risk_level"]').value
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

// Inicialização movida para o final do segundo bloco <script> (após LMS functions)
