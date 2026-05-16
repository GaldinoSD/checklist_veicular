
let lmsCourses = [];
let wizardStep = 1;
let lmsUsers = [];

async function loadLMSCourses() {
    document.getElementById('lms-loading').classList.remove('hidden');
    document.getElementById('lms-grid').classList.add('hidden');
    document.getElementById('lms-empty').classList.add('hidden');
    try {
        const res = await fetch('/api/gestao/treinamentos_lms?t=' + Date.now());
        if (res.ok) lmsCourses = await res.json();
        else lmsCourses = [];
    } catch(e) { lmsCourses = []; }

    document.getElementById('lms-loading').classList.add('hidden');
    if (!lmsCourses || lmsCourses.length === 0) {
        document.getElementById('lms-empty').classList.remove('hidden');
        return;
    }
    renderLMSGrid();
}

function renderLMSGrid() {
    const grid = document.getElementById('lms-grid');
    grid.classList.remove('hidden');
    grid.innerHTML = lmsCourses.map(c => {
        const pct = c.assigned_count > 0 ? Math.round((c.approved_count / c.assigned_count) * 100) : 0;
        const statusBadge = c.is_published
            ? `<span class="text-[8px] font-black text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-full uppercase tracking-widest">Publicado</span>`
            : `<span class="text-[8px] font-black text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded-full uppercase tracking-widest">Rascunho</span>`;
        const mandatoryBadge = c.is_mandatory ? `<span class="text-[8px] font-black text-red-500 bg-red-500/10 px-2 py-0.5 rounded-full uppercase tracking-widest">Obrigatório</span>` : '';
        const deadlineHtml = c.deadline ? `<div class="text-[9px] text-slate-400 font-bold mt-1"><i class="fa-solid fa-clock mr-1"></i>Até ${new Date(c.deadline).toLocaleDateString('pt-BR')}</div>` : '';

        return `
        <div class="card-premium p-6 flex flex-col justify-between">
            <div>
                <div class="flex items-center gap-2 flex-wrap mb-3">
                    ${statusBadge}
                    <span class="text-[8px] font-black text-slate-400 bg-slate-100 dark:bg-white/5 px-2 py-0.5 rounded-full uppercase tracking-widest">${c.category}</span>
                    ${mandatoryBadge}
                </div>
                <h4 class="text-base font-black text-slate-800 dark:text-white tracking-tight mb-1">${c.title}</h4>
                <p class="text-[11px] text-slate-500 line-clamp-2 mb-3">${c.description || 'Sem descrição'}</p>
                ${deadlineHtml}
                <div class="flex items-center gap-4 mt-3 text-[9px] font-black text-slate-400 uppercase tracking-widest">
                    <span><i class="fa-solid fa-book mr-1"></i>${c.modules_count} Módulos</span>
                    <span><i class="fa-solid fa-question mr-1"></i>${c.questions_count} Questões</span>
                </div>
                <!-- Badge Preview -->
                <div class="flex items-center gap-2 mt-3 p-2 rounded-xl" style="background:${c.badge_color}10">
                    <i class="fa-solid ${c.badge_icon} text-sm" style="color:${c.badge_color}"></i>
                    <span class="text-[9px] font-black uppercase tracking-widest" style="color:${c.badge_color}">Selo: ${c.badge_name}</span>
                </div>
            </div>

            <!-- Progress Bar -->
            ${c.is_published ? `
            <div class="mt-4 pt-4 border-t border-slate-900/5 dark:border-white/5">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-[9px] font-black text-slate-400 uppercase tracking-widest">Progresso</span>
                    <span class="text-[9px] font-black text-teal-500">${c.approved_count}/${c.assigned_count} aprovados</span>
                </div>
                <div class="h-1.5 rounded-full bg-slate-100 dark:bg-white/10 overflow-hidden">
                    <div class="h-full rounded-full bg-gradient-to-r from-teal-500 to-emerald-500" style="width:${pct}%"></div>
                </div>
            </div>
            ` : ''}

            <!-- Actions -->
            <div class="flex gap-2 mt-4">
                <button onclick="editCourse(${c.id})" class="flex-1 py-2.5 bg-slate-100 dark:bg-white/5 text-slate-600 dark:text-white rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-200 dark:hover:bg-white/10 transition-all" title="Editar">
                    <i class="fa-solid fa-pen mr-1"></i> Editar
                </button>
                ${c.is_published ? `
                <button onclick="showCourseDetail(${c.id})" class="flex-1 py-2.5 bg-teal-500/10 text-teal-600 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-teal-500/20 transition-all" title="Detalhes">
                    <i class="fa-solid fa-chart-bar mr-1"></i> Detalhes
                </button>
                ` : `
                <button onclick="openPublishModal(${c.id})" class="flex-1 py-2.5 bg-emerald-500/10 text-emerald-600 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-emerald-500/20 transition-all" title="Publicar">
                    <i class="fa-solid fa-paper-plane mr-1"></i> Publicar
                </button>
                `}
                <button onclick="deleteCourse(${c.id})" class="py-2.5 px-3 bg-red-500/10 text-red-500 rounded-xl text-[10px] font-black hover:bg-red-500/20 transition-all" title="Excluir">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </div>
        </div>`;
    }).join('');
}

// ========== WIZARD ==========
function openTrainingModal(editData) {
    wizardStep = 1;
    document.getElementById('tf-id').value = '';
    document.getElementById('tf-title').value = '';
    document.getElementById('tf-desc').value = '';
    document.getElementById('tf-category').value = 'Geral';
    document.getElementById('tf-grade').value = '70';
    document.getElementById('tf-deadline').value = '';
    document.getElementById('tf-mandatory').checked = false;
    document.getElementById('tf-badge-name').value = 'Certificado';
    document.getElementById('tf-badge-icon').value = 'fa-award';
    document.getElementById('tf-badge-color').value = '#0d9488';
    updateBadgePreview();
    document.getElementById('modules-container').innerHTML = '';
    document.getElementById('questions-container').innerHTML = '';
    document.getElementById('training-modal-title').textContent = 'Novo Treinamento';

    if (editData) {
        document.getElementById('training-modal-title').textContent = 'Editar Treinamento';
        document.getElementById('tf-id').value = editData.id;
        document.getElementById('tf-title').value = editData.title;
        document.getElementById('tf-desc').value = editData.description || '';
        document.getElementById('tf-category').value = editData.category || 'Geral';
        document.getElementById('tf-grade').value = editData.passing_grade || 70;
        document.getElementById('tf-deadline').value = editData.deadline || '';
        document.getElementById('tf-mandatory').checked = editData.is_mandatory;
        document.getElementById('tf-badge-name').value = editData.badge_name || 'Certificado';
        document.getElementById('tf-badge-icon').value = editData.badge_icon || 'fa-award';
        document.getElementById('tf-badge-color').value = editData.badge_color || '#0d9488';
        updateBadgePreview();
        (editData.modules || []).forEach(m => addModuleField(m.title, m.content));
        (editData.questions || []).forEach(q => addQuestionField(q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option));
    }

    goStep(1);
    openModal('modalTrainingForm');
}

async function editCourse(id) {
    try {
        const res = await fetch(`/api/gestao/treinamentos_lms/${id}`);
        const data = await res.json();
        openTrainingModal(data);
    } catch(e) { alert('Erro ao carregar treinamento.'); }
}

function goStep(n) {
    wizardStep = n;
    [1,2,3].forEach(s => {
        document.getElementById(`step-${s}`).classList.toggle('hidden', s !== n);
        const btn = document.getElementById(`step-btn-${s}`);
        if (s === n) {
            btn.classList.add('border-teal-500', 'text-teal-600');
            btn.classList.remove('border-transparent', 'text-slate-400');
        } else {
            btn.classList.remove('border-teal-500', 'text-teal-600');
            btn.classList.add('border-transparent', 'text-slate-400');
        }
    });
    document.getElementById('wizard-prev-btn').classList.toggle('hidden', n === 1);
    const nextBtn = document.getElementById('wizard-next-btn');
    if (n === 3) {
        nextBtn.innerHTML = '<i class="fa-solid fa-save mr-1"></i> Salvar Treinamento';
    } else {
        nextBtn.innerHTML = 'Próximo <i class="fa-solid fa-chevron-right ml-1"></i>';
    }
}

function wizardPrev() { if (wizardStep > 1) goStep(wizardStep - 1); }
function wizardNext() {
    if (wizardStep < 3) { goStep(wizardStep + 1); return; }
    saveCourse();
}

function addModuleField(title = '', content = '') {
    const c = document.getElementById('modules-container');
    const idx = c.children.length + 1;
    const div = document.createElement('div');
    div.className = 'p-4 bg-slate-50 dark:bg-white/5 border border-slate-900/5 dark:border-white/5 rounded-2xl space-y-3 relative';
    div.innerHTML = `
        <button type="button" onclick="this.closest('div').remove()" class="absolute top-3 right-3 w-7 h-7 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center hover:bg-red-500/20 transition-all"><i class="fa-solid fa-xmark text-xs"></i></button>
        <div>
            <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-1 block">Título do Módulo ${idx}</label>
            <input class="mod-title w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none" placeholder="Ex: Introdução" value="${title}">
        </div>
        <div>
            <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-1 block">Conteúdo</label>
            <textarea class="mod-content w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none resize-none" rows="5" placeholder="Escreva o conteúdo do módulo...">${content}</textarea>
        </div>`;
    c.appendChild(div);
}

function addQuestionField(qt = '', oa = '', ob = '', oc = '', od = '', correct = 'a') {
    const c = document.getElementById('questions-container');
    const idx = c.children.length + 1;
    const div = document.createElement('div');
    div.className = 'p-4 bg-amber-50/50 dark:bg-amber-500/5 border border-amber-500/10 rounded-2xl space-y-3 relative';
    div.innerHTML = `
        <button type="button" onclick="this.closest('div').remove()" class="absolute top-3 right-3 w-7 h-7 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center hover:bg-red-500/20 transition-all"><i class="fa-solid fa-xmark text-xs"></i></button>
        <div>
            <label class="text-[9px] font-black text-amber-600 uppercase tracking-widest mb-1 block">Questão ${idx}</label>
            <textarea class="q-text w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none resize-none" rows="2" placeholder="Pergunta...">${qt}</textarea>
        </div>
        <div class="grid grid-cols-2 gap-3">
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">A)</label><input class="q-a w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${oa}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">B)</label><input class="q-b w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${ob}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">C)</label><input class="q-c w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${oc}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">D)</label><input class="q-d w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${od}"></div>
        </div>
        <div>
            <label class="text-[9px] font-black text-emerald-600 uppercase tracking-widest mb-1 block">Resposta Correta</label>
            <select class="q-correct bg-white dark:bg-slate-800 border border-emerald-500/20 rounded-lg px-3 py-2 text-sm font-bold dark:text-white outline-none">
                <option value="a" ${correct==='a'?'selected':''}>A</option>
                <option value="b" ${correct==='b'?'selected':''}>B</option>
                <option value="c" ${correct==='c'?'selected':''}>C</option>
                <option value="d" ${correct==='d'?'selected':''}>D</option>
            </select>
        </div>`;
    c.appendChild(div);
}

async function saveCourse() {
    const title = document.getElementById('tf-title').value.trim();
    if (!title) { alert('Informe o título do treinamento.'); goStep(1); return; }

    const modules = [];
    document.querySelectorAll('#modules-container > div').forEach(div => {
        modules.push({
            title: div.querySelector('.mod-title').value,
            content: div.querySelector('.mod-content').value
        });
    });

    const questions = [];
    document.querySelectorAll('#questions-container > div').forEach(div => {
        questions.push({
            question_text: div.querySelector('.q-text').value,
            option_a: div.querySelector('.q-a').value,
            option_b: div.querySelector('.q-b').value,
            option_c: div.querySelector('.q-c').value,
            option_d: div.querySelector('.q-d').value,
            correct_option: div.querySelector('.q-correct').value
        });
    });

    const payload = {
        id: document.getElementById('tf-id').value || null,
        title,
        description: document.getElementById('tf-desc').value,
        category: document.getElementById('tf-category').value,
        passing_grade: document.getElementById('tf-grade').value,
        is_mandatory: document.getElementById('tf-mandatory').checked,
        deadline: document.getElementById('tf-deadline').value || null,
        badge_name: document.getElementById('tf-badge-name').value || 'Certificado',
        badge_icon: document.getElementById('tf-badge-icon').value || 'fa-award',
        badge_color: document.getElementById('tf-badge-color').value || '#0d9488',
        modules,
        questions
    };

    try {
        await fetch('/api/gestao/treinamentos_lms', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        closeModal('modalTrainingForm');
        showToast('Treinamento salvo com sucesso!', 'success');
        loadLMSCourses();
    } catch(e) { alert('Erro ao salvar.'); }
}

async function deleteCourse(id) {
    if (!confirm('Deseja excluir este treinamento?')) return;
    await fetch(`/api/gestao/treinamentos_lms/${id}`, {method: 'DELETE'});
    showToast('Treinamento excluído.', 'info');
    loadLMSCourses();
}

// ========== PUBLISH ==========
async function openPublishModal(courseId) {
    document.getElementById('pub-course-id').value = courseId;
    document.getElementById('pub-all').checked = false;
    
    const usersDiv = document.getElementById('pub-users-list');
    usersDiv.innerHTML = '<div class="py-10 text-center"><i class="fa-solid fa-spinner fa-spin text-emerald-500 text-2xl"></i></div>';
    openModal('modalTrainingPublish');

    try {
        const resTeams = await fetch('/api/gestao/equipes?t=' + Date.now());
        const teams = await resTeams.json();
        
        const resUsers = await fetch('/api/gestao/users?t=' + Date.now());
        const users = await resUsers.json();
        
        let html = '<div class="space-y-4">';
        
        // Equipes
        if(teams && teams.length > 0) {
            html += '<div class="bg-slate-50 dark:bg-white/5 p-4 rounded-xl border border-slate-900/5 dark:border-white/5">';
            html += '<h4 class="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Selecionar por Grupo</h4>';
            html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-2">';
            teams.forEach(t => {
                const memberIds = t.members.map(m => m.id).join(',');
                html += `
                    <label class="flex items-center gap-2 cursor-pointer group p-2 bg-white dark:bg-slate-800 rounded-lg border border-slate-900/10 dark:border-white/10 hover:border-emerald-500/50 transition-colors">
                        <input type="checkbox" class="team-checkbox w-4 h-4 rounded text-emerald-600 focus:ring-emerald-500" data-members="${memberIds}" onchange="toggleTeamMembers(this)">
                        <div class="w-2.5 h-2.5 rounded-full shadow-sm" style="background-color: ${t.color}"></div>
                        <span class="text-xs font-bold text-slate-700 dark:text-gray-300">${t.name}</span>
                    </label>
                `;
            });
            html += '</div></div>';
        }

        // Colaboradores individuais
        if(users && users.length > 0) {
            html += '<div class="bg-slate-50 dark:bg-white/5 p-4 rounded-xl border border-slate-900/5 dark:border-white/5">';
            html += '<h4 class="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Colaboradores Individuais</h4>';
            html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-2">';
            users.forEach(tech => {
                html += `
                    <label class="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-white/5 transition-colors">
                        <input type="checkbox" class="tech-checkbox w-4 h-4 rounded text-emerald-600 focus:ring-emerald-500" value="${tech.id}" onchange="updateTeamCheckboxes()">
                        <span class="text-xs font-bold text-slate-600 dark:text-gray-400">${tech.username}</span>
                    </label>
                `;
            });
            html += '</div></div>';
        } else {
            html += '<p class="text-xs text-slate-400 text-center py-4">Nenhum técnico encontrado.</p>';
        }
        
        html += '</div>';
        usersDiv.innerHTML = html;
        
    } catch(e) {
        usersDiv.innerHTML = '<p class="text-xs text-red-500 text-center py-4">Erro ao carregar colaboradores.</p>';
    }
}

function toggleTeamMembers(teamCb) {
    const memberIds = teamCb.getAttribute('data-members').split(',');
    document.querySelectorAll('.tech-checkbox').forEach(cb => {
        if(memberIds.includes(cb.value)) {
            cb.checked = teamCb.checked;
        }
    });
}

function updateTeamCheckboxes() {
    document.querySelectorAll('.team-checkbox').forEach(teamCb => {
        const memberIds = teamCb.getAttribute('data-members').split(',');
        const allChecked = memberIds.length > 0 && memberIds.every(id => {
            const cb = document.querySelector(`.tech-checkbox[value="${id}"]`);
            return cb && cb.checked;
        });
        teamCb.checked = allChecked;
    });
}

function togglePubAll() {
    const checked = document.getElementById('pub-all').checked;
    document.querySelectorAll('#pub-users-list input[type=checkbox]').forEach(cb => cb.checked = checked);
}

async function publishTraining() {
    const courseId = document.getElementById('pub-course-id').value;
    const assignAll = document.getElementById('pub-all').checked;
    const userIds = [];
    document.querySelectorAll('.tech-checkbox:checked').forEach(cb => {
        userIds.push(parseInt(cb.value));
    });

    try {
        await fetch(`/api/gestao/treinamentos_lms/${courseId}/publicar`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({assign_all: assignAll, user_ids: userIds})
        });
        closeModal('modalTrainingPublish');
        showToast('Treinamento publicado e enviado aos técnicos!', 'success');
        loadLMSCourses();
    } catch(e) { alert('Erro ao publicar.'); }
}

// ========== DETAIL ==========
async function showCourseDetail(id) {
    try {
        const res = await fetch(`/api/gestao/treinamentos_lms/${id}`);
        const data = await res.json();
        document.getElementById('detail-title').textContent = data.title;

        const statusColors = {
            'pendente': 'amber',
            'em_andamento': 'blue',
            'aprovado': 'emerald',
            'reprovado': 'red'
        };
        const statusLabels = {
            'pendente': 'Pendente',
            'em_andamento': 'Em Andamento',
            'aprovado': 'Aprovado',
            'reprovado': 'Reprovado'
        };

        let html = `
            <div class="grid grid-cols-3 gap-4 mb-6">
                <div class="card-premium p-4 text-center">
                    <div class="text-2xl font-black text-teal-500">${data.assignments.length}</div>
                    <div class="text-[9px] font-black text-slate-400 uppercase tracking-widest">Total Atribuídos</div>
                </div>
                <div class="card-premium p-4 text-center">
                    <div class="text-2xl font-black text-emerald-500">${data.assignments.filter(a => a.status === 'aprovado').length}</div>
                    <div class="text-[9px] font-black text-slate-400 uppercase tracking-widest">Aprovados</div>
                </div>
                <div class="card-premium p-4 text-center">
                    <div class="text-2xl font-black text-red-500">${data.assignments.filter(a => a.status === 'reprovado').length}</div>
                    <div class="text-[9px] font-black text-slate-400 uppercase tracking-widest">Reprovados</div>
                </div>
            </div>
            <div class="space-y-2">`;

        data.assignments.forEach(a => {
            const col = statusColors[a.status] || 'slate';
            const lbl = statusLabels[a.status] || a.status;
            html += `
            <div class="flex items-center justify-between p-3 bg-slate-50 dark:bg-white/5 rounded-xl border border-slate-900/5 dark:border-white/5">
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-lg bg-${col}-500/10 flex items-center justify-center text-${col}-500">
                        <i class="fa-solid ${a.status === 'aprovado' ? 'fa-circle-check' : a.status === 'reprovado' ? 'fa-circle-xmark' : 'fa-hourglass-half'} text-sm"></i>
                    </div>
                    <div>
                        <span class="text-sm font-bold text-slate-800 dark:text-white">${a.username}</span>
                        <span class="text-[8px] font-black text-${col}-500 bg-${col}-500/10 px-2 py-0.5 rounded-full uppercase tracking-widest ml-2">${lbl}</span>
                    </div>
                </div>
                <div class="text-right">
                    ${a.best_score !== null ? `<span class="text-sm font-black text-${col}-500">${a.best_score}%</span>` : '<span class="text-xs text-slate-400">—</span>'}
                    ${a.completed_at ? `<div class="text-[9px] text-slate-400">${a.completed_at}</div>` : ''}
                </div>
            </div>`;
        });

        html += '</div>';
        document.getElementById('detail-content').innerHTML = html;
        openModal('modalTrainingDetail');
    } catch(e) { alert('Erro ao carregar detalhes.'); }
}

function updateBadgePreview() {
    const icon = document.getElementById('tf-badge-icon').value;
    const color = document.getElementById('tf-badge-color').value;
    const name = document.getElementById('tf-badge-name')?.value || 'Certificado';
    const iconEl = document.getElementById('badge-preview-icon');
    const nameEl = document.getElementById('badge-preview-name');
    if (iconEl) {
        iconEl.className = `fa-solid ${icon} text-lg`;
        iconEl.style.color = color;
    }
    if (nameEl) {
        nameEl.textContent = name;
        nameEl.style.color = color;
    }
}
