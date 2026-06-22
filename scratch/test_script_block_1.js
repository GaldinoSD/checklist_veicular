
let lmsCourses = [];
let wizardStep = 1;
let lmsUsers = [];
let currentLMSSubTab = 'lms';

function switchLMSSubTab(tab) {
    currentLMSSubTab = tab;
    document.querySelectorAll('.lms-subtab-btn').forEach(btn => {
        const isTarget = (tab === 'lms' && btn.id === 'btn-lms-subtab-lms') || (tab === 'rpg_crisis' && btn.id === 'btn-lms-subtab-rpg');
        if (isTarget) {
            btn.classList.add('bg-white', 'dark:bg-white/10', 'text-slate-800', 'dark:text-white', 'shadow-sm');
            btn.classList.remove('text-slate-500', 'dark:text-slate-400');
        } else {
            btn.classList.remove('bg-white', 'dark:bg-white/10', 'text-slate-800', 'dark:text-white', 'shadow-sm');
            btn.classList.add('text-slate-500', 'dark:text-slate-400');
        }
    });

    const btnNew = document.getElementById('btn-new-training');
    if (btnNew) {
        if (tab === 'rpg_crisis') {
            btnNew.innerHTML = '<i class="fa-solid fa-plus text-xs"></i> Novo Simulador (RPG)';
            btnNew.className = "px-5 py-3 bg-amber-600 hover:bg-amber-700 text-white rounded-xl font-black text-[10px] uppercase tracking-widest shadow-lg shadow-amber-500/20 transition-all active:scale-95 flex items-center gap-2";
        } else {
            btnNew.innerHTML = '<i class="fa-solid fa-plus text-xs"></i> Novo Treinamento';
            btnNew.className = "px-5 py-3 bg-teal-600 hover:bg-teal-700 text-white rounded-xl font-black text-[10px] uppercase tracking-widest shadow-lg shadow-teal-500/20 transition-all active:scale-95 flex items-center gap-2";
        }
    }

    renderLMSGrid();
}

function updateWizardLabels() {
    const isRPG = document.getElementById('tf-course-type').value === 'rpg_crisis';
    
    // Modal Title
    document.getElementById('training-modal-title').textContent = isRPG ? 'Novo Simulador de Crise (RPG)' : 'Novo Treinamento';
    
    // Step buttons
    document.getElementById('step-btn-2').innerHTML = isRPG ? '<i class="fa-solid fa-film mr-1"></i> Cenas (RPG)' : '<i class="fa-solid fa-book mr-1"></i> Módulos';
    document.getElementById('step-btn-3').innerHTML = isRPG ? '<i class="fa-solid fa-gamepad mr-1"></i> Tomadas de Decisão' : '<i class="fa-solid fa-question-circle mr-1"></i> Questões';
    
    // Step description texts & buttons
    document.getElementById('step-2-desc').textContent = isRPG ? 'Defina a narrativa e o contexto de cada etapa/fase do simulador.' : 'Adicione os módulos de conteúdo que o técnico irá estudar.';
    document.getElementById('btn-add-module').innerHTML = isRPG ? '<i class="fa-solid fa-plus mr-1"></i> Adicionar Cena' : '<i class="fa-solid fa-plus mr-1"></i> Módulo';
    
    document.getElementById('step-3-desc').textContent = isRPG ? 'Defina as decisões e ações alternativas correspondentes a cada cena do simulador.' : 'Monte a prova com questões de múltipla escolha (A-D).';
    document.getElementById('btn-add-question').innerHTML = isRPG ? '<i class="fa-solid fa-plus mr-1"></i> Adicionar Decisão' : '<i class="fa-solid fa-plus mr-1"></i> Questão';
    
    // Wizard save/next button
    const nextBtn = document.getElementById('wizard-next-btn');
    if (wizardStep === 3) {
        nextBtn.innerHTML = isRPG ? '<i class="fa-solid fa-save mr-1"></i> Salvar Simulador' : '<i class="fa-solid fa-save mr-1"></i> Salvar Treinamento';
    }
}

async function loadLMSCourses() {
    console.log('[LMS] loadLMSCourses() called');
    document.getElementById('lms-loading').classList.remove('hidden');
    document.getElementById('lms-grid').classList.add('hidden');
    document.getElementById('lms-empty').classList.add('hidden');
    try {
        const url = '/api/gestao/treinamentos_lms?t=' + Date.now();
        console.log('[LMS] Fetching:', url);
        const res = await fetch(url);
        console.log('[LMS] Response status:', res.status);
        if (res.ok) {
            lmsCourses = await res.json();
            console.log('[LMS] Courses loaded:', lmsCourses.length, lmsCourses);
        } else {
            console.error('[LMS] API error:', res.status, res.statusText);
            lmsCourses = [];
        }
    } catch(e) {
        console.error('[LMS] Fetch exception:', e);
        lmsCourses = [];
    }

    document.getElementById('lms-loading').classList.add('hidden');
    renderLMSGrid();
}

function renderLMSGrid() {
    const grid = document.getElementById('lms-grid');
    const filteredCourses = lmsCourses.filter(c => {
        const type = c.course_type || 'lms';
        return type === currentLMSSubTab;
    });

    if (!filteredCourses || filteredCourses.length === 0) {
        grid.classList.add('hidden');
        document.getElementById('lms-empty').classList.remove('hidden');
        return;
    }

    document.getElementById('lms-empty').classList.add('hidden');
    grid.classList.remove('hidden');
    grid.innerHTML = filteredCourses.map(c => {
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
                <button onclick="openPublishModal(${c.id})" class="flex-1 py-2.5 bg-emerald-500/10 text-emerald-600 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-emerald-500/20 transition-all" title="${c.is_published ? 'Enviar para novos usuários' : 'Publicar e Enviar'}">
                    <i class="fa-solid fa-paper-plane mr-1"></i> ${c.is_published ? 'Enviar' : 'Publicar'}
                </button>
                ${c.is_published ? `
                <button onclick="showCourseDetail(${c.id})" class="py-2.5 px-3 bg-teal-500/10 text-teal-600 rounded-xl text-[10px] font-black hover:bg-teal-500/20 transition-all" title="Ver Resultados">
                    <i class="fa-solid fa-chart-bar"></i>
                </button>
                ` : ''}
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
    document.getElementById('tf-course-type').value = currentLMSSubTab;
    document.getElementById('tf-category').value = 'Geral';
    document.getElementById('tf-grade').value = '70';
    document.getElementById('tf-deadline').value = '';
    document.getElementById('tf-mandatory').checked = false;
    document.getElementById('tf-badge-name').value = 'Certificado';
    document.getElementById('tf-badge-icon').value = 'fa-award';
    document.getElementById('tf-badge-color').value = '#0d9488';
    document.getElementById('tf-allow-retake').checked = false;
    updateBadgePreview();
    document.getElementById('modules-container').innerHTML = '';
    document.getElementById('questions-container').innerHTML = '';
    document.getElementById('training-modal-title').textContent = 'Novo Treinamento';

    if (editData) {
        document.getElementById('training-modal-title').textContent = 'Editar Treinamento';
        document.getElementById('tf-id').value = editData.id;
        document.getElementById('tf-title').value = editData.title;
        document.getElementById('tf-desc').value = editData.description || '';
        document.getElementById('tf-course-type').value = editData.course_type || 'lms';
        document.getElementById('tf-category').value = editData.category || 'Geral';
        document.getElementById('tf-grade').value = editData.passing_grade || 70;
        document.getElementById('tf-deadline').value = editData.deadline || '';
        document.getElementById('tf-mandatory').checked = editData.is_mandatory;
        document.getElementById('tf-badge-name').value = editData.badge_name || 'Certificado';
        document.getElementById('tf-badge-icon').value = editData.badge_icon || 'fa-award';
        document.getElementById('tf-badge-color').value = editData.badge_color || '#0d9488';
        document.getElementById('tf-allow-retake').checked = editData.allow_retake || false;
        updateBadgePreview();
        const isRPG = (editData.course_type === 'rpg_crisis');
        if (isRPG) {
            (editData.modules || []).forEach((m, idx) => {
                const q = (editData.questions || [])[idx] || null;
                addModuleField(m.title, m.content, m.image_path, m.video_path, q);
            });
        } else {
            (editData.modules || []).forEach(m => addModuleField(m.title, m.content, m.image_path, m.video_path));
            (editData.questions || []).forEach(q => addQuestionField(q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.correct_option));
        }
    }

    goStep(1);
    updateWizardLabels();
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
    const isRPG = document.getElementById('tf-course-type').value === 'rpg_crisis';
    wizardStep = n;
    
    // Hide Step 3 tab button in RPG mode
    const step3Btn = document.getElementById('step-btn-3');
    if (step3Btn) {
        step3Btn.classList.toggle('hidden', isRPG);
    }
    
    [1,2,3].forEach(s => {
        const el = document.getElementById(`step-${s}`);
        if (el) el.classList.toggle('hidden', s !== n);
        
        const btn = document.getElementById(`step-btn-${s}`);
        if (btn) {
            if (s === n) {
                btn.classList.add('border-teal-500', 'text-teal-600');
                btn.classList.remove('border-transparent', 'text-slate-400');
            } else {
                btn.classList.remove('border-teal-500', 'text-teal-600');
                btn.classList.add('border-transparent', 'text-slate-400');
            }
        }
    });
    
    document.getElementById('wizard-prev-btn').classList.toggle('hidden', n === 1);
    const nextBtn = document.getElementById('wizard-next-btn');
    
    if (isRPG && n === 2) {
        nextBtn.innerHTML = '<i class="fa-solid fa-save mr-1"></i> Salvar Simulador';
    } else if (!isRPG && n === 3) {
        nextBtn.innerHTML = '<i class="fa-solid fa-save mr-1"></i> Salvar Treinamento';
    } else {
        nextBtn.innerHTML = 'Próximo <i class="fa-solid fa-chevron-right ml-1"></i>';
    }
}

function wizardPrev() { if (wizardStep > 1) goStep(wizardStep - 1); }
function wizardNext() {
    const isRPG = document.getElementById('tf-course-type').value === 'rpg_crisis';
    const maxSteps = isRPG ? 2 : 3;
    if (wizardStep < maxSteps) { goStep(wizardStep + 1); return; }
    saveCourse();
}

function addModuleField(title = '', content = '', image_path = '', video_path = '', questionData = null) {
    const isRPG = document.getElementById('tf-course-type').value === 'rpg_crisis';
    const c = document.getElementById('modules-container');
    const idx = c.children.length + 1;
    const div = document.createElement('div');
    div.className = 'p-4 bg-slate-50 dark:bg-white/5 border border-slate-900/5 dark:border-white/5 rounded-2xl space-y-3 relative';
    
    // Fallback or values for questionData
    const qText = questionData ? (questionData.question_text || '') : '';
    const qA = questionData ? (questionData.option_a || '') : '';
    const qB = questionData ? (questionData.option_b || '') : '';
    const qC = questionData ? (questionData.option_c || '') : '';
    const qD = questionData ? (questionData.option_d || '') : '';
    const qCorrect = questionData ? (questionData.correct_option || 'a') : 'a';

    let html = `
        <button type="button" onclick="this.closest('div').remove()" class="absolute top-3 right-3 w-7 h-7 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center hover:bg-red-500/20 transition-all"><i class="fa-solid fa-xmark text-xs"></i></button>
        <div>
            <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-1 block">${isRPG ? `Título da Cena ${idx}` : `Título do Módulo ${idx}`}</label>
            <input aria-label="${isRPG ? 'Título da Cena' : 'Título do Módulo'}" class="mod-title w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none" placeholder="${isRPG ? 'Ex: Cena 1: Curto Circuito' : 'Ex: Introdução'}" value="${title}">
        </div>
        <div>
            <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-1 block">${isRPG ? 'Narrativa / Descrição da Cena' : 'Conteúdo'}</label>
            <textarea class="mod-content w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none resize-none" rows="5" placeholder="${isRPG ? 'Descreva o cenário e a situação em que o técnico se encontra...' : 'Escreva o conteúdo do módulo...'}">${content}</textarea>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 pt-3 border-t border-slate-900/5 dark:border-white/5">
            <!-- Upload de Imagem -->
            <div class="space-y-2">
                <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest block">${isRPG ? 'Imagem da Cena (Fundo)' : 'Imagem do Módulo (Opcional - Máx 5MB)'}</label>
                <div class="flex items-center gap-3">
                    <input type="hidden" class="mod-image-path" value="${image_path}">
                    <input aria-label="input" type="file" accept="image/*" class="hidden image-file-input" onchange="uploadModuleMedia(this, 'image')">
                    
                    <button type="button" onclick="this.previousElementSibling.click()" class="px-3 py-2 bg-slate-200 dark:bg-white/10 hover:bg-slate-300 dark:hover:bg-white/15 text-slate-700 dark:text-slate-200 rounded-xl text-xs font-bold transition-all flex items-center gap-2">
                        <i class="fa-solid fa-image"></i>
                        <span>Escolher Imagem</span>
                    </button>
                    
                    <span class="upload-status-image text-[10px] font-bold text-slate-400 hidden">
                        <i class="fa-solid fa-spinner fa-spin mr-1"></i>Enviando...
                    </span>
                </div>
                
                <!-- Preview de Imagem -->
                <div class="image-preview-container flex items-center gap-2 mt-2 ${image_path ? '' : 'hidden'}">
                    <img src="${image_path || ''}" class="w-20 h-20 object-cover rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm">
                    <button type="button" onclick="clearModuleMedia(this, 'image')" class="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-all" title="Remover Imagem">
                        <i class="fa-solid fa-trash-can text-sm"></i>
                    </button>
                </div>
            </div>

            <!-- Upload de Vídeo -->
            <div class="space-y-2">
                <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest block">${isRPG ? 'Vídeo da Cena (Fundo)' : 'Vídeo do Módulo (Opcional - Máx 25MB)'}</label>
                <div class="flex items-center gap-3">
                    <input type="hidden" class="mod-video-path" value="${video_path}">
                    <input aria-label="input" type="file" accept="video/mp4,video/webm" class="hidden video-file-input" onchange="uploadModuleMedia(this, 'video')">
                    
                    <button type="button" onclick="this.previousElementSibling.click()" class="px-3 py-2 bg-slate-200 dark:bg-white/10 hover:bg-slate-300 dark:hover:bg-white/15 text-slate-700 dark:text-slate-200 rounded-xl text-xs font-bold transition-all flex items-center gap-2">
                        <i class="fa-solid fa-video"></i>
                        <span>Escolher Vídeo</span>
                    </button>
                    
                    <span class="upload-status-video text-[10px] font-bold text-slate-400 hidden">
                        <i class="fa-solid fa-spinner fa-spin mr-1"></i>Enviando...
                    </span>
                </div>
                
                <!-- Preview de Vídeo -->
                <div class="video-preview-container flex items-center gap-2 mt-2 ${video_path ? '' : 'hidden'}">
                    <video src="${video_path || ''}" controls class="w-40 h-24 object-cover rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm"></video>
                    <button type="button" onclick="clearModuleMedia(this, 'video')" class="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-all" title="Remover Vídeo">
                        <i class="fa-solid fa-trash-can text-sm"></i>
                    </button>
                </div>
            </div>
        </div>`;

    if (isRPG) {
        html += `
        <div class="rpg-decision-section mt-4 pt-4 border-t-2 border-dashed border-amber-500/20 bg-amber-500/5 -mx-4 -mb-4 p-4 rounded-b-2xl space-y-3">
            <div class="flex items-center gap-2 text-amber-600 dark:text-amber-400">
                <i class="fa-solid fa-gamepad"></i>
                <span class="text-[10px] font-black uppercase tracking-widest">Tomada de Decisão da Cena</span>
            </div>
            <div>
                <label class="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-1 block">Ação / Decisão Requerida *</label>
                <textarea class="rpg-q-text w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-xl px-3 py-2 text-sm font-bold dark:text-white outline-none resize-none" rows="2" placeholder="O que o técnico precisará decidir nesta cena? Ex: Qual sua ação imediata frente a esta crise?">${qText}</textarea>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="text-[8px] font-black text-slate-400 uppercase tracking-widest block">Ação A</label>
                    <input aria-label="Opção..." class="rpg-q-a w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" placeholder="Opção..." value="${qA}">
                </div>
                <div>
                    <label class="text-[8px] font-black text-slate-400 uppercase tracking-widest block">Ação B</label>
                    <input aria-label="Opção..." class="rpg-q-b w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" placeholder="Opção..." value="${qB}">
                </div>
                <div>
                    <label class="text-[8px] font-black text-slate-400 uppercase tracking-widest block">Ação C</label>
                    <input aria-label="Opção..." class="rpg-q-c w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" placeholder="Opção..." value="${qC}">
                </div>
                <div>
                    <label class="text-[8px] font-black text-slate-400 uppercase tracking-widest block">Ação D</label>
                    <input aria-label="Opção..." class="rpg-q-d w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" placeholder="Opção..." value="${qD}">
                </div>
            </div>
            <div>
                <label class="text-[9px] font-black text-emerald-600 dark:text-emerald-400 uppercase tracking-widest mb-1 block">Ação Correta / Mais Segura *</label>
                <select class="rpg-q-correct bg-white dark:bg-slate-800 border border-emerald-500/20 rounded-lg px-3 py-2 text-sm font-bold dark:text-white outline-none font-bold">
                    <option value="a" ${qCorrect==='a'?'selected':''}>A</option>
                    <option value="b" ${qCorrect==='b'?'selected':''}>B</option>
                    <option value="c" ${qCorrect==='c'?'selected':''}>C</option>
                    <option value="d" ${qCorrect==='d'?'selected':''}>D</option>
                </select>
            </div>
        </div>`;
    }

    div.innerHTML = html;
    c.appendChild(div);
}

async function uploadModuleMedia(input, type) {
    const file = input.files[0];
    if (!file) return;

    // Validações frontend rápidas
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (type === 'image') {
        const allowedImage = ['.jpg', '.jpeg', '.png', '.webp'];
        if (!allowedImage.includes(ext)) {
            alert('Formato de imagem inválido. Use JPG, JPEG, PNG ou WEBP.');
            input.value = '';
            return;
        }
        if (file.size > 5 * 1024 * 1024) {
            alert('A imagem excede o limite de 5MB.');
            input.value = '';
            return;
        }
    } else if (type === 'video') {
        const allowedVideo = ['.mp4', '.webm'];
        if (!allowedVideo.includes(ext)) {
            alert('Formato de vídeo inválido. Use MP4 ou WEBM.');
            input.value = '';
            return;
        }
        if (file.size > 25 * 1024 * 1024) {
            alert('O vídeo excede o limite de 25MB.');
            input.value = '';
            return;
        }
    }

    const parent = input.closest('.space-y-2');
    const statusSpan = parent.querySelector(`.upload-status-${type}`);
    const previewContainer = parent.querySelector(`.${type}-preview-container`);
    const pathInput = parent.querySelector(`.mod-${type}-path`);

    if (statusSpan) statusSpan.classList.remove('hidden');

    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    try {
        const res = await fetch('/api/gestao/treinamentos_lms/upload_media', {
            method: 'POST',
            body: formData
        });
        const result = await res.json();
        
        if (!res.ok) {
            throw new Error(result.error || 'Erro desconhecido no servidor');
        }

        pathInput.value = result.path;

        // Renderiza preview dinâmico
        if (type === 'image') {
            previewContainer.innerHTML = `
                <img src="${result.path}" class="w-20 h-20 object-cover rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm">
                <button type="button" onclick="clearModuleMedia(this, 'image')" class="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-all" title="Remover Imagem">
                    <i class="fa-solid fa-trash-can text-sm"></i>
                </button>
            `;
        } else {
            previewContainer.innerHTML = `
                <video src="${result.path}" controls class="w-40 h-24 object-cover rounded-xl border border-slate-900/10 dark:border-white/10 shadow-sm"></video>
                <button type="button" onclick="clearModuleMedia(this, 'video')" class="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-all" title="Remover Vídeo">
                    <i class="fa-solid fa-trash-can text-sm"></i>
                </button>
            `;
        }
        previewContainer.classList.remove('hidden');
        if (statusSpan) {
            statusSpan.innerHTML = '<i class="fa-solid fa-circle-check text-emerald-500 mr-1"></i>Enviado!';
            setTimeout(() => {
                statusSpan.classList.add('hidden');
                statusSpan.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i>Enviando...';
            }, 2000);
        }
    } catch (e) {
        console.error(e);
        alert('Falha no upload: ' + e.message);
        if (statusSpan) statusSpan.classList.add('hidden');
        input.value = '';
    }
}

function clearModuleMedia(button, type) {
    const previewContainer = button.closest(`.${type}-preview-container`);
    const parentContainer = previewContainer.parentElement;
    const pathInput = parentContainer.querySelector(`.mod-${type}-path`);
    const fileInput = parentContainer.querySelector(`.${type}-file-input`);

    pathInput.value = '';
    fileInput.value = '';
    previewContainer.classList.add('hidden');
    previewContainer.innerHTML = '';
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
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">A)</label><input aria-label="input" class="q-a w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${oa}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">B)</label><input aria-label="input" class="q-b w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${ob}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">C)</label><input aria-label="input" class="q-c w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${oc}"></div>
            <div><label class="text-[8px] font-black text-slate-400 uppercase tracking-widest">D)</label><input aria-label="input" class="q-d w-full bg-white dark:bg-slate-800 border border-slate-900/5 dark:border-white/5 rounded-lg px-3 py-2 text-xs font-bold dark:text-white outline-none mt-1" value="${od}"></div>
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

    const isRPG = document.getElementById('tf-course-type').value === 'rpg_crisis';
    const modules = [];
    const questions = [];

    document.querySelectorAll('#modules-container > div').forEach(div => {
        modules.push({
            title: div.querySelector('.mod-title').value,
            content: div.querySelector('.mod-content').value,
            image_path: div.querySelector('.mod-image-path').value || null,
            video_path: div.querySelector('.mod-video-path').value || null
        });

        if (isRPG) {
            questions.push({
                question_text: div.querySelector('.rpg-q-text').value,
                option_a: div.querySelector('.rpg-q-a').value,
                option_b: div.querySelector('.rpg-q-b').value,
                option_c: div.querySelector('.rpg-q-c').value,
                option_d: div.querySelector('.rpg-q-d').value,
                correct_option: div.querySelector('.rpg-q-correct').value
            });
        }
    });

    if (!isRPG) {
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
    }

    const payload = {
        id: document.getElementById('tf-id').value || null,
        title,
        description: document.getElementById('tf-desc').value,
        course_type: document.getElementById('tf-course-type').value,
        category: document.getElementById('tf-category').value,
        passing_grade: document.getElementById('tf-grade').value,
        is_mandatory: document.getElementById('tf-mandatory').checked,
        deadline: document.getElementById('tf-deadline').value || null,
        badge_name: document.getElementById('tf-badge-name').value || 'Certificado',
        badge_icon: document.getElementById('tf-badge-icon').value || 'fa-award',
        badge_color: document.getElementById('tf-badge-color').value || '#0d9488',
        allow_retake: document.getElementById('tf-allow-retake').checked,
        modules,
        questions
    };

    try {
        const res = await fetch('/api/gestao/treinamentos_lms', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Erro ao salvar no servidor');
        
        closeModal('modalTrainingForm');
        showToast('Treinamento salvo com sucesso!', 'success');
        loadLMSCourses();
    } catch(e) { 
        console.error(e);
        alert('Erro ao salvar treinamento. Verifique os dados e tente novamente.'); 
    }
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
                        <input aria-label="input" type="checkbox" class="team-checkbox w-4 h-4 rounded text-emerald-600 focus:ring-emerald-500" data-members="${memberIds}" onchange="toggleTeamMembers(this)">
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
                        <input aria-label="input" type="checkbox" class="tech-checkbox w-4 h-4 rounded text-emerald-600 focus:ring-emerald-500" value="${tech.id}" onchange="updateTeamCheckboxes()">
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
        const res = await fetch(`/api/gestao/treinamentos_lms/${courseId}/publicar`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({assign_all: assignAll, user_ids: userIds})
        });
        if (!res.ok) throw new Error('Erro ao publicar');
        
        closeModal('modalTrainingPublish');
        showToast('Treinamento enviado aos técnicos selecionados!', 'success');
        loadLMSCourses();
    } catch(e) { 
        console.error(e);
        alert('Erro ao enviar treinamento.'); 
    }
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

        // --- Ranking Section ---
        const ranking = [...data.assignments]
            .filter(a => a.best_score !== null)
            .sort((a, b) => b.best_score - a.best_score);

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

            ${ranking.length > 0 ? `
            <div class="mb-8">
                <h5 class="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-trophy text-amber-500"></i> Ranking de Performance
                </h5>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    ${ranking.slice(0, 3).map((a, idx) => {
                        const colors = ['text-amber-500 bg-amber-500/10', 'text-slate-400 bg-slate-400/10', 'text-amber-700 bg-amber-700/10'];
                        const medals = ['fa-medal', 'fa-medal', 'fa-medal'];
                        return `
                        <div class="p-4 rounded-2xl border border-slate-900/5 dark:border-white/5 bg-white dark:bg-white/5 relative overflow-hidden group">
                            <div class="absolute -right-2 -top-2 opacity-10 group-hover:opacity-20 transition-opacity">
                                <i class="fa-solid ${medals[idx]} text-5xl"></i>
                            </div>
                            <div class="flex items-center gap-3">
                                <div class="w-10 h-10 rounded-xl ${colors[idx]} flex items-center justify-center text-lg font-black shadow-inner">
                                    ${idx + 1}º
                                </div>
                                <div class="flex-1 min-w-0">
                                    <div class="text-xs font-black text-slate-800 dark:text-white truncate">${a.username.split(' ')[0]}</div>
                                    <div class="text-[14px] font-black text-teal-500">${a.best_score}%</div>
                                </div>
                            </div>
                        </div>
                        `;
                    }).join('')}
                </div>
            </div>
            ` : ''}

            <h5 class="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Lista Geral de Colaboradores</h5>
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

let currentReportRecords = [];

const headersMap = {
    'lms': { col1: 'Título do Treinamento', col2: 'Colaborador', col3: 'Nota / Pontuação', col4: 'Resultado' },
    'supervisao': { col1: 'Supervisor', col2: 'Técnicos Presentes', col3: 'Ação Recomendada', col4: 'Irregularidades' },
    'rfo': { col1: 'Número RFO', col2: 'Título e Tipo', col3: 'Técnico Responsável', col4: 'Status' },
    'atividades': { col1: 'Responsável', col2: 'Tipo de Vistoria', col3: 'Cliente', col4: 'Status' },
    'rota': { col1: 'Supervisor', col2: 'Localização', col3: 'Técnicos Presentes', col4: 'Status' },
    'reunioes': { col1: 'Título Reunião', col2: 'Assunto Principal', col3: 'Responsável', col4: 'Status' },
    'escalas': { col1: 'Tipo de Escala', col2: 'Equipes Operacionais', col3: 'Técnicos Escalados', col4: 'Obs' },
    'geradores': { col1: 'Nome / Identificação', col2: 'Localização', col3: 'Capacidade / Nível', col4: 'Status' },
    'encerramento': { col1: 'Pátio Operacional', col2: 'Horário Fechamento', col3: 'Técnicos de Plantão', col4: 'Observações' },
    'anotacoes': { col1: 'Título da Anotação', col2: 'Categoria', col3: 'Criador', col4: 'Prioridade' },
    'tarefas': { col1: 'Título da Tarefa', col2: 'Responsável', col3: 'Prioridade', col4: 'Status' }
};

function initRelatoriosTab() {
    const startInput = document.getElementById('report_start');
    const endInput = document.getElementById('report_end');
    
    // Set default dates if not set: from first day of month to today
    const today = new Date();
    const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
    
    const formatDate = (d) => {
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    if (!startInput.value) {
        startInput.value = formatDate(firstDay);
    }
    if (!endInput.value) {
        endInput.value = formatDate(today);
    }

    // Set change listeners if not set
    const inputs = ['report_type', 'report_start', 'report_end', 'report_user'];
    inputs.forEach(id => {
        const el = document.getElementById(id);
        if (el && !el.dataset.listenerAttached) {
            el.addEventListener('change', () => carregarRelatorioPreview());
            el.dataset.listenerAttached = 'true';
        }
    });

    carregarRelatorioPreview();
}

async function carregarRelatorioPreview() {
    const type = document.getElementById('report_type').value;
    const start = document.getElementById('report_start').value;
    const end = document.getElementById('report_end').value;
    const user_id = document.getElementById('report_user').value;
    const previewContent = document.getElementById('relatorio-preview-content');
    const metricsContainer = document.getElementById('relatorio-metrics-container');

    if (!start || !end) {
        return;
    }

    // Render skeleton loading
    previewContent.innerHTML = `
        <div class="space-y-4 p-6 w-full animate-premium">
            <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded w-1/4 animate-pulse"></div>
            <div class="space-y-3 mt-4">
                <div class="grid grid-cols-5 gap-4">
                    <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded col-span-1 animate-pulse"></div>
                    <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded col-span-1 animate-pulse"></div>
                    <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded col-span-1 animate-pulse"></div>
                    <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded col-span-1 animate-pulse"></div>
                    <div class="h-4 bg-slate-200 dark:bg-slate-700/50 rounded col-span-1 animate-pulse"></div>
                </div>
                <div class="h-10 bg-slate-100 dark:bg-slate-800/30 rounded w-full animate-pulse"></div>
                <div class="h-10 bg-slate-100 dark:bg-slate-800/30 rounded w-full animate-pulse"></div>
                <div class="h-10 bg-slate-100 dark:bg-slate-800/30 rounded w-full animate-pulse"></div>
            </div>
        </div>
    `;

    // Clear search
    document.getElementById('report_search').value = '';

    try {
        const params = new URLSearchParams({
            type: type,
            start_date: start,
            end_date: end,
            user_id: user_id
        });

        const res = await fetch(`/api/gestao/relatorios/preview?${params.toString()}`);
        if (!res.ok) {
            throw new Error('Falha ao carregar preview');
        }

        const data = await res.json();
        currentReportRecords = data.records || [];
        const metrics = data.metrics || {};

        // 1. Render Metrics dynamically
        let metricsHtml = '';
        Object.entries(metrics).forEach(([key, val]) => {
            metricsHtml += `
                <div class="p-5 rounded-[2rem] border border-slate-900/5 dark:border-white/5 bg-white/50 dark:bg-slate-800/50 backdrop-blur-md shadow-sm transition-all hover:scale-105 duration-300">
                    <div class="text-slate-400 dark:text-slate-500 text-[9px] font-black uppercase tracking-wider mb-1">${key}</div>
                    <div class="text-lg font-black text-slate-800 dark:text-white">${val}</div>
                </div>
            `;
        });
        if (!metricsHtml) {
            metricsHtml = `
                <div class="p-5 rounded-[2rem] border border-slate-900/5 dark:border-white/5 bg-white/50 dark:bg-slate-800/50 backdrop-blur-md shadow-sm">
                    <div class="text-slate-400 text-[9px] font-black uppercase tracking-wider mb-1">Status</div>
                    <div class="text-lg font-black text-slate-800 dark:text-white">Sem Métricas</div>
                </div>
            `;
        }
        metricsContainer.innerHTML = metricsHtml;

        // 2. Render Table
        renderTabelaRelatorios(currentReportRecords, type);

    } catch (e) {
        console.error(e);
        previewContent.innerHTML = `
            <div class="flex flex-col items-center justify-center text-center py-16">
                <div class="w-16 h-16 rounded-full bg-rose-500/10 flex items-center justify-center mb-4">
                    <i class="fa-solid fa-circle-xmark text-2xl text-rose-500"></i>
                </div>
                <h4 class="text-sm font-black text-slate-700 dark:text-slate-200">Erro ao Carregar Dados</h4>
                <p class="text-xs text-slate-500 mt-1 max-w-xs font-medium">Verifique os filtros selecionados ou recarregue a página.</p>
            </div>
        `;
    }
}

function renderTabelaRelatorios(records, type) {
    const previewContent = document.getElementById('relatorio-preview-content');
    
    if (!records || records.length === 0) {
        previewContent.innerHTML = `
            <div class="flex flex-col items-center justify-center text-center py-16">
                <div class="w-16 h-16 rounded-full bg-slate-50 dark:bg-white/5 flex items-center justify-center mb-4">
                    <i class="fa-solid fa-folder-open text-2xl text-slate-400"></i>
                </div>
                <h4 class="text-sm font-black text-slate-700 dark:text-slate-200">Nenhum Registro Encontrado</h4>
                <p class="text-xs text-slate-500 mt-1 max-w-xs font-medium">Não há dados correspondentes ao período e filtros selecionados.</p>
            </div>
        `;
        return;
    }

    const headers = headersMap[type] || { col1: 'Coluna 1', col2: 'Coluna 2', col3: 'Coluna 3', col4: 'Coluna 4' };

    let rowsHtml = '';
    records.forEach(r => {
        let statusBadge = '';
        if (r.status === 'success') {
            statusBadge = `<span class="px-3 py-1.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-full text-[9px] font-black uppercase tracking-wider">${r.col4}</span>`;
        } else if (r.status === 'warning') {
            statusBadge = `<span class="px-3 py-1.5 bg-amber-500/10 text-amber-600 dark:text-amber-400 rounded-full text-[9px] font-black uppercase tracking-wider">${r.col4}</span>`;
        } else if (r.status === 'danger') {
            statusBadge = `<span class="px-3 py-1.5 bg-rose-500/10 text-rose-600 dark:text-rose-400 rounded-full text-[9px] font-black uppercase tracking-wider">${r.col4}</span>`;
        } else {
            statusBadge = `<span class="px-3 py-1.5 bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded-full text-[9px] font-black uppercase tracking-wider">${r.col4 || r.status}</span>`;
        }

        rowsHtml += `
            <tr class="hover:bg-slate-50 dark:hover:bg-white/5 transition-all duration-150 border-b border-slate-900/5 dark:border-white/5">
                <td class="py-3.5 pl-3 font-bold text-slate-800 dark:text-white whitespace-nowrap">${r.date}</td>
                <td class="py-3.5 font-bold text-slate-700 dark:text-slate-300 max-w-[200px] truncate" title="${r.col1}">${r.col1}</td>
                <td class="py-3.5 font-medium text-slate-600 dark:text-slate-400 max-w-[200px] truncate" title="${r.col2}">${r.col2}</td>
                <td class="py-3.5 font-bold text-slate-700 dark:text-slate-300 max-w-[200px] truncate" title="${r.col3}">${r.col3}</td>
                <td class="py-3.5 pr-3 text-right whitespace-nowrap">${statusBadge}</td>
            </tr>
        `;
    });

    previewContent.innerHTML = `
        <table class="w-full text-left border-collapse">
            <thead>
                <tr class="border-b border-slate-900/5 dark:border-white/5 text-[9px] font-black text-slate-400 uppercase tracking-widest">
                    <th class="pb-3 pl-3">Data/Hora</th>
                    <th class="pb-3">${headers.col1}</th>
                    <th class="pb-3">${headers.col2}</th>
                    <th class="pb-3">${headers.col3}</th>
                    <th class="pb-3 text-right pr-3">${headers.col4}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-900/5 dark:divide-white/5 text-xs">
                ${rowsHtml}
            </tbody>
        </table>
    `;
}

function filtrarTabelaRelatorioPreview() {
    const searchVal = document.getElementById('report_search').value.toLowerCase();
    const type = document.getElementById('report_type').value;

    if (!searchVal) {
        renderTabelaRelatorios(currentReportRecords, type);
        return;
    }

    const filtered = currentReportRecords.filter(r => {
        return (r.date && r.date.toLowerCase().includes(searchVal)) ||
               (r.col1 && r.col1.toLowerCase().includes(searchVal)) ||
               (r.col2 && r.col2.toLowerCase().includes(searchVal)) ||
               (r.col3 && r.col3.toLowerCase().includes(searchVal)) ||
               (r.col4 && r.col4.toLowerCase().includes(searchVal));
    });

    renderTabelaRelatorios(filtered, type);
}

async function gerarRelatorioPDF() {
    const type = document.getElementById('report_type').value;
    const start = document.getElementById('report_start').value;
    const end = document.getElementById('report_end').value;
    const user_id = document.getElementById('report_user').value;

    if (!start || !end) {
        return alert('Por favor, selecione as datas inicial e final.');
    }

    try {
        showToast('Gerando relatório... Isso pode levar alguns segundos.', 'info');
        
        const params = new URLSearchParams({
            type: type,
            start_date: start,
            end_date: end,
            user_id: user_id
        });

        // Abrir em nova aba para download
        window.open(`/api/gestao/relatorios/gerar?${params.toString()}`, '_blank');

    } catch (e) {
        console.error(e);
        alert('Erro ao processar solicitação de relatório.');
    }
}

let powerBiConfig = {
    panels: 1,
    layout: 'cols', // 'cols', 'rows', 'focus'
    height: 'fit'   // 'fit', 'sm', 'md', 'lg', 'xl'
};

const pbiUrl = "[]";

function setPowerBiPanels(num) {
    powerBiConfig.panels = num;
    updatePowerBiLayout();
}

function setPowerBiLayout(layout) {
    powerBiConfig.layout = layout;
    updatePowerBiLayout();
}

function setPowerBiHeight(height) {
    powerBiConfig.height = height;
    updatePowerBiLayout();
}

function updatePowerBiLayout() {
    const grid = document.getElementById('powerbi-grid');
    if (!grid) return;

    const container = document.getElementById('powerbi-container');
    if (container) {
        if (powerBiConfig.height === 'fit') {
            container.classList.add('pbi-height-fit');
        } else {
            container.classList.remove('pbi-height-fit');
        }
    }

    // Reset container classes
    grid.className = 'grid gap-6 w-full p-4';
    
    // Get cards
    const card1 = document.getElementById('pbi-card-1');
    const card2 = document.getElementById('pbi-card-2');
    const card3 = document.getElementById('pbi-card-3');
    
    const iframe1 = document.getElementById('powerbi-iframe-1');
    const iframe2 = document.getElementById('powerbi-iframe-2');
    const iframe3 = document.getElementById('powerbi-iframe-3');

    // Reset layout spans
    card1.className = card1.className.replace(/md:col-span-\d|md:row-span-\d/g, '').replace(/\s+/g, ' ').trim();
    card2.className = card2.className.replace(/md:col-span-\d|md:row-span-\d/g, '').replace(/\s+/g, ' ').trim();
    card3.className = card3.className.replace(/md:col-span-\d|md:row-span-\d/g, '').replace(/\s+/g, ' ').trim();

    // Reset frame heights
    const iframes = [iframe1, iframe2, iframe3];
    iframes.forEach(f => {
        if (f && f.parentElement) {
            f.parentElement.className = 'w-full flex-1 relative';
        }
    });

    // Update active visual states on control buttons
    document.querySelectorAll('.btn-pbi-panel').forEach(btn => {
        const val = parseInt(btn.dataset.value);
        if (val === powerBiConfig.panels) {
            btn.classList.add('bg-purple-600', 'text-white');
            btn.classList.remove('text-slate-600', 'dark:text-slate-400');
        } else {
            btn.classList.remove('bg-purple-600', 'text-white');
            btn.classList.add('text-slate-600', 'dark:text-slate-400');
        }
    });

    // Update active visual states on height buttons
    document.querySelectorAll('.btn-pbi-height').forEach(btn => {
        if (btn.dataset.value === powerBiConfig.height) {
            btn.classList.add('bg-purple-600', 'text-white');
            btn.classList.remove('text-slate-600', 'dark:text-slate-400');
        } else {
            btn.classList.remove('bg-purple-600', 'text-white');
            btn.classList.add('text-slate-600', 'dark:text-slate-400');
        }
    });

    // Hide/show alignment option based on selected panel count
    const alignContainer = document.getElementById('pbi-align-container');
    if (alignContainer) {
        if (powerBiConfig.panels > 1) {
            alignContainer.classList.remove('hidden');
            alignContainer.classList.add('flex');
        } else {
            alignContainer.classList.remove('flex');
            alignContainer.classList.add('hidden');
        }
    }

    // Toggle alignment buttons based on number of panels
    const btnFocus = document.querySelector('.btn-pbi-layout[data-value="focus"]');
    if (btnFocus) {
        if (powerBiConfig.panels === 3) {
            btnFocus.classList.remove('hidden');
        } else {
            btnFocus.classList.add('hidden');
            if (powerBiConfig.layout === 'focus') {
                powerBiConfig.layout = 'cols';
            }
        }
    }

    document.querySelectorAll('.btn-pbi-layout').forEach(btn => {
        if (btn.dataset.value === powerBiConfig.layout) {
            btn.classList.add('bg-purple-600', 'text-white');
            btn.classList.remove('text-slate-600', 'dark:text-slate-400');
        } else {
            btn.classList.remove('bg-purple-600', 'text-white');
            btn.classList.add('text-slate-600', 'dark:text-slate-400');
        }
    });

    // Apply layout logic
    if (powerBiConfig.panels === 1) {
        card1.classList.remove('hidden');
        card2.classList.add('hidden');
        card3.classList.add('hidden');
        
        iframe2.src = '';
        iframe3.src = '';
        
        grid.classList.add('grid-cols-1');
        iframe1.parentElement.classList.add('min-h-[600px]', 'md:min-h-[750px]');
    } 
    else if (powerBiConfig.panels === 2) {
        card1.classList.remove('hidden');
        card2.classList.remove('hidden');
        card3.classList.add('hidden');
        
        if (!iframe2.getAttribute('src')) {
            iframe2.src = pbiUrl;
        }
        iframe3.src = '';

        if (powerBiConfig.layout === 'cols') {
            grid.classList.add('grid-cols-1', 'md:grid-cols-2');
            iframe1.parentElement.classList.add('min-h-[500px]', 'md:min-h-[650px]');
            iframe2.parentElement.classList.add('min-h-[500px]', 'md:min-h-[650px]');
        } else {
            grid.classList.add('grid-cols-1');
            iframe1.parentElement.classList.add('min-h-[400px]', 'md:min-h-[500px]');
            iframe2.parentElement.classList.add('min-h-[400px]', 'md:min-h-[500px]');
        }
    } 
    else if (powerBiConfig.panels === 3) {
        card1.classList.remove('hidden');
        card2.classList.remove('hidden');
        card3.classList.remove('hidden');
        
        if (!iframe2.getAttribute('src')) {
            iframe2.src = pbiUrl;
        }
        if (!iframe3.getAttribute('src')) {
            iframe3.src = pbiUrl;
        }

        if (powerBiConfig.layout === 'cols') {
            grid.classList.add('grid-cols-1', 'md:grid-cols-3');
            iframe1.parentElement.classList.add('min-h-[400px]', 'md:min-h-[600px]');
            iframe2.parentElement.classList.add('min-h-[400px]', 'md:min-h-[600px]');
            iframe3.parentElement.classList.add('min-h-[400px]', 'md:min-h-[600px]');
        } 
        else if (powerBiConfig.layout === 'rows') {
            grid.classList.add('grid-cols-1');
            iframe1.parentElement.classList.add('min-h-[350px]', 'md:min-h-[450px]');
            iframe2.parentElement.classList.add('min-h-[350px]', 'md:min-h-[450px]');
            iframe3.parentElement.classList.add('min-h-[350px]', 'md:min-h-[450px]');
        } 
        else if (powerBiConfig.layout === 'focus') {
            grid.classList.add('grid-cols-1', 'md:grid-cols-3', 'md:grid-rows-2');
            
            card1.classList.add('md:col-span-2', 'md:row-span-2');
            iframe1.parentElement.classList.add('min-h-[500px]', 'md:min-h-[680px]');
            
            iframe2.parentElement.classList.add('min-h-[250px]', 'md:min-h-[328px]');
            iframe3.parentElement.classList.add('min-h-[250px]', 'md:min-h-[328px]');
        }
    }

    // Apply custom height override if not 'fit'
    if (powerBiConfig.height && powerBiConfig.height !== 'fit') {
        const heightMap = {
            'sm': 400,
            'md': 600,
            'lg': 800,
            'xl': 1000
        };
        const baseHeight = heightMap[powerBiConfig.height] || 600;
        
        if (powerBiConfig.layout === 'focus' && powerBiConfig.panels === 3) {
            // Card 1 gets full baseHeight
            iframe1.parentElement.className = 'w-full relative';
            iframe1.parentElement.style.height = `${baseHeight}px`;
            iframe1.parentElement.style.minHeight = `${baseHeight}px`;
            iframe1.parentElement.style.flex = 'none';
            
            // Cards 2 & 3 get half height
            const halfHeight = Math.round(baseHeight / 2);
            [iframe2, iframe3].forEach(iframe => {
                if (iframe && iframe.parentElement) {
                    iframe.parentElement.className = 'w-full relative';
                    iframe.parentElement.style.height = `${halfHeight}px`;
                    iframe.parentElement.style.minHeight = `${halfHeight}px`;
                    iframe.parentElement.style.flex = 'none';
                }
            });
        } else {
            iframes.forEach(f => {
                if (f && f.parentElement) {
                    f.parentElement.className = 'w-full relative';
                    f.parentElement.style.height = `${baseHeight}px`;
                    f.parentElement.style.minHeight = `${baseHeight}px`;
                    f.parentElement.style.flex = 'none';
                }
            });
        }
        
        // In fullscreen mode, the cards also need height: auto so they don't stretch/squeeze to 100vh
        if (document.fullscreenElement) {
            [card1, card2, card3].forEach(card => {
                if (card) {
                    card.style.height = 'auto';
                    card.style.minHeight = 'auto';
                    card.style.flex = 'none';
                }
            });
        }
    } else {
        // Reset inline styles if height is 'fit'
        iframes.forEach(f => {
            if (f && f.parentElement) {
                f.parentElement.style.height = '';
                f.parentElement.style.minHeight = '';
                f.parentElement.style.flex = '';
            }
        });
        [card1, card2, card3].forEach(card => {
            if (card) {
                card.style.height = '';
                card.style.minHeight = '';
                card.style.flex = '';
            }
        });
    }
    
    // Trigger loading animation
    initPowerBITab();
}

function initPowerBITab() {
    const spinner = document.getElementById('powerbi-loading');
    if (!spinner) return;
    
    spinner.classList.remove('hidden');
    
    const visibleIframes = [];
    for (let i = 1; i <= 3; i++) {
        const card = document.getElementById(`pbi-card-${i}`);
        const iframe = document.getElementById(`powerbi-iframe-${i}`);
        if (card && !card.classList.contains('hidden') && iframe) {
            visibleIframes.push(iframe);
        }
    }
    
    let loadedCount = 0;
    if (visibleIframes.length === 0) {
        spinner.classList.add('hidden');
        return;
    }
    
    visibleIframes.forEach(iframe => {
        iframe.onload = function() {
            loadedCount++;
            if (loadedCount >= visibleIframes.length) {
                spinner.classList.add('hidden');
            }
        };
    });
    
    // Fallback de carregamento (máximo 5 segundos)
    setTimeout(() => {
        spinner.classList.add('hidden');
    }, 5000);
}

function togglePowerBiFullscreen() {
    const container = document.getElementById('powerbi-container');
    if (!container) return;
    
    if (!document.fullscreenElement) {
        container.requestFullscreen().catch(err => {
            alert(`Erro ao tentar ativar tela cheia: ${err.message}`);
        });
    } else {
        document.exitFullscreen();
    }
}

function togglePowerBiControls(show) {
    const controlsBar = document.getElementById('pbi-controls-bar');
    const restoreBtn = document.getElementById('pbi-restore-controls');
    
    if (show) {
        if (controlsBar) {
            controlsBar.classList.remove('hidden');
            controlsBar.classList.add('flex');
        }
        if (restoreBtn) {
            restoreBtn.classList.add('hidden');
        }
    } else {
        if (controlsBar) {
            controlsBar.classList.remove('flex');
            controlsBar.classList.add('hidden');
        }
        if (restoreBtn) {
            restoreBtn.classList.remove('hidden');
        }
    }
}

// Restaura os controles se o usuário sair do modo tela cheia usando a tecla ESC
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        togglePowerBiControls(true);
    }
    // Força atualização de layout para aplicar/remover os estilos inline específicos do fullscreen
    updatePowerBiLayout();
});


// ========== INICIALIZAÇÃO ==========
// Deve ficar AQUI (após todas as funções, incluindo LMS) para evitar ReferenceError
const urlParams = new URLSearchParams(window.location.search);
const initialTab = urlParams.get('tab') || 'equipes';
switchTab(initialTab);
