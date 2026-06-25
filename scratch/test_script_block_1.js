
window.onerror = function(message, source, lineno, colno, error) {
    const errorMsg = message + " (Linha: " + lineno + ", Col: " + colno + ")";
    console.error("DEBUG ERROR:", errorMsg);
    let banner = document.getElementById('debug-error-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'debug-error-banner';
        banner.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; background: #dc2626; color: white; padding: 12px; z-index: 999999; font-family: monospace; font-size: 11px; font-weight: bold; border-bottom: 3px solid #7f1d1d; display: flex; align-items: center; justify-content: space-between;';
        document.body.appendChild(banner);
    }
    banner.innerHTML = '<span>⚠️ ERRO JS: ' + errorMsg + '</span><button onclick="this.parentElement.remove()" style="background: rgba(0,0,0,0.2); border: none; color: white; padding: 4px 8px; border-radius: 6px; cursor: pointer;">Fechar</button>';
};

(function(){
    // Funções globais declaradas de forma segura e dinâmica
    window.openNovaVistoriaModal = function() {
        const modalNova = document.getElementById('modalNovaVistoria');
        if (modalNova) {
            modalNova.showModal();
            document.body.classList.add('overflow-hidden');
        } else {
            console.error("modalNovaVistoria not found!");
        }
    }
    window.closeNovaVistoriaModal = function() {
        const modalNova = document.getElementById('modalNovaVistoria');
        if (modalNova) {
            modalNova.close();
            document.body.classList.remove('overflow-hidden');
        }
    }
    window.openVerVistoriaModal = function() {
        const modalVer = document.getElementById('modalVerVistoria');
        if (modalVer) {
            modalVer.showModal();
            document.body.classList.add('overflow-hidden');
        }
    }
    window.closeVerVistoriaModal = function() {
        const modalVer = document.getElementById('modalVerVistoria');
        if (modalVer) {
            modalVer.close();
            document.body.classList.remove('overflow-hidden');
        }
    }

    // Inicialização de seletores e eventos de forma segura ao carregar o DOM
    document.addEventListener("DOMContentLoaded", () => {
        const modalNova = document.getElementById('modalNovaVistoria');
        if (!modalNova) return;

        const labelMappings = {
            carro: {
                para_choque_dianteiro: "Para-choque dianteiro",
                para_choque_traseiro: "Para-choque traseiro",
                lateral_esquerda: "Lateral esquerda",
                lateral_direita: "Lateral direita",
                capo: "Capô",
                teto: "Teto",
                porta_malas: "Porta-malas",
                retrovisores: "Retrovisores",
                farois_lanternas: "Faróis / Lanternas",
                vidros_parabrisa: "Vidros / Para-brisa",
                pneus: "Pneus",
                calotas: "Calotas"
            },
            moto: {
                para_choque_dianteiro: "Guidão e Manetes",
                para_choque_traseiro: "Relação (Corrente/Coroa)",
                lateral_esquerda: "Lateral esquerda",
                lateral_direita: "Lateral direita",
                capo: "Tanque de Combustível",
                teto: "Assento / Banco",
                porta_malas: "Baú / Bauleto",
                retrovisores: "Retrovisores",
                farois_lanternas: "Farol / Lanterna",
                vidros_parabrisa: "Escapamento / Motor",
                pneus: "Pneus (Dianteiro/Traseiro)",
                calotas: "Rodas / Raios"
            }
        };

        const subLabelsConfig = {
            carro: {
                "pneus-de": [true, "DE"],
                "pneus-dd": [true, "DD"],
                "pneus-te": [true, "TE"],
                "pneus-td": [true, "TD"],
                "calotas-de": [true, "DE"],
                "calotas-dd": [true, "DD"],
                "calotas-te": [true, "TE"],
                "calotas-td": [true, "TD"],
                "farois_lanternas-fe": [true, "Farol Esq"],
                "farois_lanternas-fd": [true, "Farol Dir"],
                "farois_lanternas-le": [true, "Lanterna Esq"],
                "farois_lanternas-ld": [true, "Lanterna Dir"],
                "vidros_parabrisa-diant": [true, "Dianteiro"],
                "vidros_parabrisa-tras": [true, "Traseiro"],
                "vidros_parabrisa-vlde": [true, "Vidro Lat. Diant. Esq."],
                "vidros_parabrisa-vldd": [true, "Vidro Lat. Diant. Dir."],
                "vidros_parabrisa-vlte": [true, "Vidro Lat. Tras. Esq."],
                "vidros_parabrisa-vltd": [true, "Vidro Lat. Tras. Dir."]
            },
            moto: {
                "pneus-de": [true, "D (Dianteiro)"],
                "pneus-dd": [false, ""],
                "pneus-te": [true, "T (Traseiro)"],
                "pneus-td": [false, ""],
                "calotas-de": [true, "D (Dianteira)"],
                "calotas-dd": [false, ""],
                "calotas-te": [true, "T (Traseira)"],
                "calotas-td": [false, ""],
                "farois_lanternas-fe": [true, "Farol (Dianteiro)"],
                "farois_lanternas-fd": [false, ""],
                "farois_lanternas-le": [true, "Lanterna (Traseira)"],
                "farois_lanternas-ld": [false, ""],
                "vidros_parabrisa-diant": [true, "Escapamento / Motor"],
                "vidros_parabrisa-tras": [false, ""],
                "vidros_parabrisa-vlde": [false, ""],
                "vidros_parabrisa-vldd": [false, ""],
                "vidros_parabrisa-vlte": [false, ""],
                "vidros_parabrisa-vltd": [false, ""]
            }
        };

        const modalSel = document.getElementById("modal_vehicle_id");
        const modalKm = document.getElementById("modal_km");
        if(modalSel && modalKm){
            modalSel.addEventListener("change", () => {
                const opt = modalSel.options[modalSel.selectedIndex];
                const vkm = opt?.getAttribute("data-km");
                if(vkm !== null && vkm !== undefined){
                    modalKm.value = vkm;
                }

                // ALTERNAR SVGs E AJUSTAR LABELS COM BASE NO TIPO DE VEÍCULO
                const vtype = opt?.getAttribute("data-type") || "carro";
                const svgCarro = document.getElementById("nova_svg_container_carro");
                const svgMoto = document.getElementById("nova_svg_container_moto");
                
                if(svgCarro && svgMoto) {
                    if(vtype === "moto") {
                        svgCarro.classList.add("hidden");
                        svgMoto.classList.remove("hidden");
                    } else {
                        svgCarro.classList.remove("hidden");
                        svgMoto.classList.add("hidden");
                    }
                }
                
                // Renomear labels dos cards do modal
                const activeMapping = labelMappings[vtype] || labelMappings.carro;
                for (const [key, label] of Object.entries(activeMapping)) {
                    const lblEl = document.querySelector(`[data-label-key="modal-${key}"]`);
                    if (lblEl) {
                        lblEl.textContent = label;
                    }
                }
                
                // Ajustar sub-checkboxes do modal (visibilidade e texto)
                const subConfig = subLabelsConfig[vtype] || subLabelsConfig.carro;
                for (const [subKey, config] of Object.entries(subConfig)) {
                    const [visible, text] = config;
                    const cbLabelEl = document.querySelector(`[data-sub-label="modal-${subKey}"]`);
                    if (cbLabelEl) {
                        if (visible) {
                            cbLabelEl.classList.remove("hidden");
                            const spanEl = cbLabelEl.querySelector("span");
                            if (spanEl) spanEl.textContent = text;
                        } else {
                            cbLabelEl.classList.add("hidden");
                            // Desmarcar se ocultado
                            const inputEl = cbLabelEl.querySelector("input");
                            if (inputEl) {
                                inputEl.checked = false;
                                inputEl.dispatchEvent(new Event("change"));
                            }
                        }
                    }
                }
            });
        }

        const modalStatusHidden = document.getElementById("modal_status_geral");
        const modalBadge = document.getElementById("modalStatusBadge");
        const modalStatusText = document.getElementById("modalStatusText");
        const modalSelects = Array.from(modalNova.querySelectorAll("[data-item-status]"));

        function updateModalStatusGeral(){
            const temAvaria = modalSelects.some(s => s.value === "avaria");
            if(modalStatusHidden) modalStatusHidden.value = temAvaria ? "avarias" : "ok";
            
            if(modalBadge && modalStatusText) {
                if(temAvaria) {
                    modalBadge.className = "h-[34px] inline-flex items-center gap-2 px-3 rounded-xl border bg-amber-500/10 border-amber-500/20 text-amber-600 text-xs font-black";
                    modalBadge.querySelector("span").textContent = "⚠️";
                    modalStatusText.textContent = "Com avarias";
                } else {
                    modalBadge.className = "h-[34px] inline-flex items-center gap-2 px-3 rounded-xl border bg-emerald-500/10 border-emerald-500/20 text-emerald-600 text-xs font-black";
                    modalBadge.querySelector("span").textContent = "✅";
                    modalStatusText.textContent = "OK";
                }
            }
        }

        // Sincronizar os checkboxes de sub-partes com o SVG do veículo
        modalNova.querySelectorAll("input[data-part-sub]").forEach(cb => {
            cb.addEventListener("change", () => {
                const key = cb.getAttribute("data-part-sub");
                const sub = cb.value;
                const select = modalNova.querySelector(`select[data-item-status="${key}"]`);
                
                // Atualiza o SVG correspondente
                const partEls = modalNova.querySelectorAll(`#modal_svg_nova [data-part="${key}"][data-sub="${sub}"], #modal_svg_nova_moto [data-part="${key}"][data-sub="${sub}"]`);
                partEls.forEach(partEl => {
                    if (cb.checked) {
                        partEl.classList.add("part-avaria");
                        partEl.classList.remove("part-ok");
                    } else {
                        partEl.classList.add("part-ok");
                        partEl.classList.remove("part-avaria");
                    }
                });
                
                // Se algum checkbox daquela parte estiver marcado, o status vira "avaria"
                const anyChecked = Array.from(modalNova.querySelectorAll(`input[data-part-sub="${key}"]:checked`)).length > 0;
                if (select) {
                    const prevVal = select.value;
                    select.value = anyChecked ? "avaria" : "ok";
                    if (prevVal !== select.value) {
                        // Atualiza exibição dos wraps de foto/obs
                        const wrap = document.getElementById("modal_wrap_" + key);
                        if (wrap) wrap.classList.toggle("hidden", select.value !== "avaria");
                        updateModalStatusGeral();
                    }
                }
            });
        });

        modalSelects.forEach(s => {
            function apply(){
                const key = s.getAttribute("data-item-status");
                const wrap = document.getElementById("modal_wrap_" + key);
                if(wrap){
                    wrap.classList.toggle("hidden", s.value !== "avaria");
                }
                
                // Fazer a cor do SVG refletir alterações no dropdown de status
                const svgParts = document.querySelectorAll(`#modal_svg_nova [data-part="${key}"], #modal_svg_nova_moto [data-part="${key}"]`);
                if (s.value === "avaria") {
                    const checkboxes = modalNova.querySelectorAll(`input[data-part-sub="${key}"]`);
                    if (checkboxes.length > 0) {
                        // Apenas atualiza o SVG com base nos checkboxes marcados
                        checkboxes.forEach(cb => {
                            const sub = cb.value;
                            const partEls = modalNova.querySelectorAll(`#modal_svg_nova [data-part="${key}"][data-sub="${sub}"], #modal_svg_nova_moto [data-part="${key}"][data-sub="${sub}"]`);
                            partEls.forEach(partEl => {
                                if (cb.checked) {
                                    partEl.classList.add("part-avaria");
                                    partEl.classList.remove("part-ok");
                                } else {
                                    partEl.classList.add("part-ok");
                                    partEl.classList.remove("part-avaria");
                                }
                            });
                        });
                    } else {
                        // Itens sem sub-partes
                        svgParts.forEach(part => {
                            part.classList.add("part-avaria");
                            part.classList.remove("part-ok");
                        });
                    }
                } else {
                    // Desmarca todos os checkboxes se mudou para OK
                    const checkboxes = modalNova.querySelectorAll(`input[data-part-sub="${key}"]`);
                    checkboxes.forEach(cb => {
                        cb.checked = false;
                    });
                    svgParts.forEach(part => {
                        part.classList.add("part-ok");
                        part.classList.remove("part-avaria");
                    });
                }
                
                updateModalStatusGeral();
            }
            s.addEventListener("change", apply);
            apply();
        });

        // Clique no mapa 2D do veículo alterna status e foca no card (Nova Vistoria)
        document.querySelectorAll("#modal_svg_nova [data-part], #modal_svg_nova_moto [data-part]").forEach(part => {
            part.addEventListener("click", () => {
                const key = part.getAttribute("data-part");
                const sub = part.getAttribute("data-sub");
                const s = modalNova.querySelector(`select[data-item-status="${key}"]`);
                
                if (s) {
                    if (sub) {
                        // Tem sub-partes: alterna o checkbox específico
                        const cb = modalNova.querySelector(`input[data-part-sub="${key}"][value="${sub}"]`);
                        if (cb) {
                            cb.checked = !cb.checked;
                            cb.dispatchEvent(new Event("change"));
                        }
                    } else {
                        // Sem sub-partes: alterna o status do select inteiro
                        s.value = s.value === "ok" ? "avaria" : "ok";
                        s.dispatchEvent(new Event("change"));
                    }

                    // Se marcou como avaria, faz scroll suave até o card
                    if (s.value === "avaria") {
                        const card = document.getElementById(`modal_card_${key}`);
                        if (card) {
                            card.scrollIntoView({ behavior: "smooth", block: "center" });
                            card.classList.add("ring-2", "ring-amber-500", "scale-[1.02]");
                            setTimeout(() => {
                                card.classList.remove("ring-2", "ring-amber-500", "scale-[1.02]");
                            }, 1500);
                        }
                    }
                }
            });
        });

        // Interceptar submit para prependar os metadados [parts:sub1,sub2...] nas observações
        const modalForm = modalNova.querySelector("form");
        if (modalForm) {
            modalForm.addEventListener("submit", (e) => {
                ["pneus", "calotas", "vidros_parabrisa", "farois_lanternas", "retrovisores"].forEach(key => {
                    const select = modalForm.querySelector(`select[name="${key}"]`);
                    const obsInput = modalForm.querySelector(`input[name="obs_${key}"]`);
                    if (select && obsInput) {
                        if (select.value === "avaria") {
                            const checkedSubs = Array.from(modalForm.querySelectorAll(`input[data-part-sub="${key}"]:checked`)).map(cb => cb.value);
                            if (checkedSubs.length > 0) {
                                const originalVal = obsInput.value.replace(/^\[parts:[^\]]+\]\s*/, "");
                                obsInput.value = `[parts:${checkedSubs.join(",")}] ${originalVal}`.trim();
                            } else {
                                obsInput.value = obsInput.value.replace(/^\[parts:[^\]]+\]\s*/, "");
                            }
                        } else {
                            obsInput.value = obsInput.value.replace(/^\[parts:[^\]]+\]\s*/, "");
                        }
                    }
                });
            });
        }

        // Ver Vistoria Lógica
        const modalVer = document.getElementById('modalVerVistoria');
        window.openVerVistoriaModal = function() {
            modalVer.showModal();
            document.body.classList.add('overflow-hidden');
        }
        window.closeVerVistoriaModal = function() {
            modalVer.close();
            document.body.classList.remove('overflow-hidden');
        }

        window.openVistoriaDetailModal = function(vistoriaId) {
            openVerVistoriaModal();
            
            document.getElementById('verModalLoader').classList.remove('hidden');
            document.getElementById('verModalContent').classList.add('hidden');
            
            // Reset SVG parts to ok initially
            const svgVerParts = document.querySelectorAll("#modal_svg_ver [data-part], #modal_svg_ver_moto [data-part]");
            svgVerParts.forEach(part => {
                part.className.baseVal = "transition duration-200 part-ok";
                part.onclick = null;
            });

            fetch(`/vistorias/${vistoriaId}?format=json`)
                .then(response => {
                    if (!response.ok) throw new Error("Erro ao buscar vistoria");
                    return response.json();
                })
                .then(data => {
                    document.getElementById('verModalTitle').textContent = `Vistoria #${data.id}`;
                    document.getElementById('verModalSubtitle').textContent = `${data.created_at}`;
                    document.getElementById('verModalVehiclePlate').textContent = data.plate;
                    document.getElementById('verModalKM').textContent = data.km ? `${data.km} KM` : "-";
                    
                    // Configura link do PDF
                    document.getElementById('verModalPdfBtn').href = `/vistorias/${data.id}/pdf`;
                    
                    // Configura botão de exclusão no rodapé do modal
                    document.getElementById('verModalDeleteContainer').innerHTML = `
                        <form action="/vistorias/${data.id}/excluir" method="POST" class="inline" onsubmit="return confirm('Deseja realmente excluir esta vistoria e todas as fotos associadas?');">
                            <button type="submit" class="px-5 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-600 rounded-xl text-xs font-black uppercase tracking-wider transition-all">
                                <i class="fa-solid fa-trash-can mr-1"></i> Excluir Vistoria
                            </button>
                        </form>
                    `;
                    
                    const turnoFormatted = data.turno === 'inicio' ? 'Início do Expediente' : (data.turno === 'durante' ? 'Durante Expediente' : 'Fim do Expediente');
                    const localFormatted = data.local ? ` · ${data.local}` : '';
                    document.getElementById('verModalTurnoLocal').textContent = `${turnoFormatted}${localFormatted}`;
                    
                    const badge = document.getElementById('verModalStatusBadge');
                    if (data.status_geral === 'avarias') {
                        badge.className = "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-lg text-xs font-bold border mt-0.5 bg-amber-500/10 border-amber-500/20 text-amber-700";
                        badge.innerHTML = "<span>⚠️ Com avarias</span>";
                    } else {
                        badge.className = "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-lg text-xs font-bold border mt-0.5 bg-emerald-500/10 border-emerald-500/20 text-emerald-700";
                        badge.innerHTML = "<span>✅ OK</span>";
                    }
                    
                    // Alternar o SVG de detalhes com base no tipo
                    const verSvgCarro = document.getElementById("ver_svg_container_carro");
                    const verSvgMoto = document.getElementById("ver_svg_container_moto");
                    if (verSvgCarro && verSvgMoto) {
                        if (data.vehicle_type === "moto") {
                            verSvgCarro.classList.add("hidden");
                            verSvgMoto.classList.remove("hidden");
                        } else {
                            verSvgCarro.classList.remove("hidden");
                            verSvgMoto.classList.add("hidden");
                        }
                    }
                    
                    const obsContainer = document.getElementById('verModalObsContainer');
                    const obsText = document.getElementById('verModalObservacoes');
                    if (data.observacoes && data.observacoes.trim() !== '') {
                        obsText.textContent = data.observacoes;
                        obsContainer.classList.remove('hidden');
                    } else {
                        obsContainer.classList.add('hidden');
                    }
                    
                    const grid = document.getElementById('verModalItemsGrid');
                    grid.innerHTML = "";
                    
                    const subLabels = (data.vehicle_type === "moto") ? {
                        de: "Dianteiro (D)",
                        te: "Traseiro (T)",
                        diant: "Escapamento / Motor",
                        fe: "Farol (Dianteiro)",
                        le: "Lanterna (Traseira)",
                        esq: "Esquerdo",
                        dir: "Direito"
                    } : {
                        de: "Dianteiro Esquerdo (DE)", dd: "Dianteiro Direito (DD)",
                        te: "Traseiro Esquerdo (TE)", td: "Traseiro Direito (TD)",
                        diant: "Dianteiro", tras: "Traseiro",
                        fe: "Farol Esquerdo", fd: "Farol Direito",
                        le: "Lanterna Esquerda", ld: "Lanterna Direita",
                        esq: "Esquerdo", dir: "Direito",
                        vlde: "Vidro Lateral Diant. Esq.", vldd: "Vidro Lateral Diant. Dir.",
                        vlte: "Vidro Lateral Tras. Esq.", vltd: "Vidro Lateral Tras. Dir."
                    };

                    data.items.forEach(item => {
                        const itemEl = document.createElement('div');
                        itemEl.className = "p-4 rounded-2xl border border-slate-900/5 dark:border-white/5 bg-slate-900/[0.01] dark:bg-white/[0.01]";
                        
                        let cleanObs = item.obs || "";
                        let activeSubs = [];
                        const partsMatch = cleanObs.match(/^\[parts:([^\]]+)\]\s*(.*)/);
                        if (partsMatch) {
                            activeSubs = partsMatch[1].split(",");
                            cleanObs = partsMatch[2];
                        }
                        
                        let statusBadgeHTML = "";
                        if (item.status === 'avaria') {
                            statusBadgeHTML = `<span class="px-2 py-0.5 rounded-lg text-[10px] font-black uppercase bg-amber-500/10 border border-amber-500/20 text-amber-600">Avaria</span>`;
                            
                            // Highlight SVG part on the read-only visualizer map
                            if (activeSubs.length > 0) {
                                activeSubs.forEach(sub => {
                                    const matchingParts = document.querySelectorAll(`#modal_svg_ver [data-part="${item.key}"][data-sub="${sub}"], #modal_svg_ver_moto [data-part="${item.key}"][data-sub="${sub}"]`);
                                    matchingParts.forEach(part => {
                                        part.className.baseVal = "transition duration-200 part-avaria";
                                        part.onclick = () => {
                                            itemEl.scrollIntoView({ behavior: "smooth", block: "center" });
                                            itemEl.classList.add("ring-2", "ring-amber-500", "scale-[1.02]");
                                            setTimeout(() => {
                                                itemEl.classList.remove("ring-2", "ring-amber-500", "scale-[1.02]");
                                            }, 1500);
                                        };
                                    });
                                });
                            } else {
                                // Fallback para destacar todas as partes do item caso não tenha sub-parte salva
                                const matchingParts = document.querySelectorAll(`#modal_svg_ver [data-part="${item.key}"], #modal_svg_ver_moto [data-part="${item.key}"]`);
                                matchingParts.forEach(part => {
                                    part.className.baseVal = "transition duration-200 part-avaria";
                                    part.onclick = () => {
                                        itemEl.scrollIntoView({ behavior: "smooth", block: "center" });
                                        itemEl.classList.add("ring-2", "ring-amber-500", "scale-[1.02]");
                                        setTimeout(() => {
                                            itemEl.classList.remove("ring-2", "ring-amber-500", "scale-[1.02]");
                                        }, 1500);
                                    };
                                });
                            }
                        } else {
                            statusBadgeHTML = `<span class="px-2 py-0.5 rounded-lg text-[10px] font-black uppercase bg-emerald-500/10 border border-emerald-500/20 text-emerald-600">OK</span>`;
                        }
                        
                        let detailsHTML = "";
                        if (item.status === 'avaria') {
                            const obsInfo = cleanObs.trim() !== "" ? cleanObs : "Nenhuma descrição fornecida.";
                            
                            let subInfoHTML = "";
                            if (activeSubs.length > 0) {
                                const subTextList = activeSubs.map(s => subLabels[s] || s).join(", ");
                                subInfoHTML = `
                                    <div class="mb-2">
                                        <span class="text-[9px] font-black text-slate-400 uppercase tracking-wider block mb-0.5">Partes Afetadas</span>
                                        <span class="text-xs font-bold text-slate-700 dark:text-slate-350 bg-slate-900/5 dark:bg-white/5 px-2 py-1 rounded-md border border-slate-900/5 dark:border-white/5">${subTextList}</span>
                                    </div>
                                `;
                            }

                            let photosHTML = "";
                            if (item.fotos && item.fotos.length > 0) {
                                photosHTML = `
                                    <div class="mt-2 pt-2 border-t border-slate-900/5 dark:border-white/5">
                                        <span class="text-[9px] font-black text-slate-400 uppercase tracking-wider block mb-1">Fotos do Item</span>
                                        <div class="grid grid-cols-3 gap-2">
                                            ${item.fotos.map(filename => `
                                                <a href="/static/vistorias_fotos/${filename}" target="_blank" class="block overflow-hidden rounded-xl border border-slate-900/10 dark:border-white/10 hover:opacity-80 transition-all">
                                                    <img src="/static/vistorias_fotos/${filename}" class="w-full h-16 object-cover" alt="Foto da avaria" />
                                                </a>
                                            `).join("")}
                                        </div>
                                    </div>
                                `;
                            }
                            
                            detailsHTML = `
                                <div class="mt-3 pt-3 border-t border-dashed border-slate-900/10 dark:border-white/10">
                                    ${subInfoHTML}
                                    <span class="text-[9px] font-black text-slate-400 uppercase tracking-wider block mb-0.5">Descrição da Avaria</span>
                                    <p class="text-xs text-slate-700 dark:text-slate-350 font-bold bg-amber-500/5 p-2 rounded-lg border border-amber-500/10">${obsInfo}</p>
                                    ${photosHTML}
                                </div>
                            `;
                        }
                        
                        itemEl.innerHTML = `
                            <div class="flex items-center justify-between gap-2">
                                <span class="text-xs font-bold text-slate-800 dark:text-white">${item.label}</span>
                                ${statusBadgeHTML}
                            </div>
                            ${detailsHTML}
                        `;
                        grid.appendChild(itemEl);
                    });
                    
                    document.getElementById('verModalLoader').classList.add('hidden');
                    document.getElementById('verModalContent').classList.remove('hidden');
                })
                .catch(err => {
                    console.error(err);
                    document.getElementById('verModalSubtitle').textContent = "Falha ao carregar detalhes.";
                    document.getElementById('verModalLoader').innerHTML = `
                        <div class="text-red-500 text-3xl mb-2">❌</div>
                        <p class="text-xs font-bold text-red-500 uppercase tracking-widest">Falha de Conexão</p>
                        <button onclick="closeVerVistoriaModal()" class="mt-4 px-4 py-2 bg-slate-800 text-white rounded-xl text-xs font-bold uppercase">Fechar</button>
                    `;
                });
        };

        // Auto-open modal se open_id estiver nos parâmetros da URL
        const urlParams = new URLSearchParams(window.location.search);
        const openId = urlParams.get('open_id');
        if (openId) {
            openVistoriaDetailModal(openId);
            
            // Limpa parâmetro open_id sem recarregar
            urlParams.delete('open_id');
            const cleanUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
            window.history.replaceState({}, '', cleanUrl);
        }
    });
})();

function toggleMonthGroup(index) {
    const tbody = document.getElementById(`tbody-group-${index}`);
    const chevron = document.getElementById(`chevron-group-${index}`);
    if (tbody && chevron) {
        tbody.classList.toggle('hidden');
        chevron.classList.toggle('rotate-180');
    }
}
