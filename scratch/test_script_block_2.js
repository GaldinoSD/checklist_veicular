
let ocrWorker = null;
let isScanning = false;
let videoStream = null;

async function initOCRWorker() {
    if (!ocrWorker) {
        document.getElementById('ocr-status').innerText = 'Carregando IA...';
        ocrWorker = await Tesseract.createWorker('eng');
        await ocrWorker.setParameters({
            tessedit_char_whitelist: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        });
    }
}

async function startPlateOCR() {
    const scannerDialog = document.getElementById('ocrScannerModal');
    scannerDialog.classList.remove('hidden');
    scannerDialog.showModal();
    document.getElementById('ocr-status').innerText = 'Iniciando câmera...';
    
    const video = document.getElementById('ocr-video');
    try {
        videoStream = await navigator.mediaDevices.getUserMedia({
            video: { 
                facingMode: 'environment',
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        });
        video.srcObject = videoStream;
        video.setAttribute('playsinline', true);
        video.play();
        
        isScanning = true;
        
        await initOCRWorker();
        document.getElementById('ocr-status').innerText = 'Enquadre a placa';
        scanLoop();
        
    } catch (err) {
        console.error("Erro ao abrir câmera:", err);
        alert("Não foi possível acessar a câmera traseira do celular.");
        closeOCRScanner();
    }
}

function closeOCRScanner() {
    isScanning = false;
    if (videoStream) {
        videoStream.getTracks().forEach(track => track.stop());
        videoStream = null;
    }
    const scannerDialog = document.getElementById('ocrScannerModal');
    if (scannerDialog.open) {
        scannerDialog.close();
    }
    scannerDialog.classList.add('hidden');
}

function levenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    Math.min(
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    )
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

async function scanLoop() {
    if (!isScanning) return;
    
    const video = document.getElementById('ocr-video');
    if (video && video.readyState === video.HAVE_ENOUGH_DATA) {
        const videoWidth = video.videoWidth;
        const videoHeight = video.videoHeight;
        
        const rectWidth = videoWidth * 0.5;
        const rectHeight = videoHeight * 0.2;
        const rectX = (videoWidth - rectWidth) / 2;
        const rectY = (videoHeight - rectHeight) / 2;
        
        const scaleFactor = 3;
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = rectWidth * scaleFactor;
        canvas.height = rectHeight * scaleFactor;
        
        ctx.drawImage(video, rectX, rectY, rectWidth, rectHeight, 0, 0, canvas.width, canvas.height);
        
        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const pixels = imgData.data;
        for (let i = 0; i < pixels.length; i += 4) {
            const r = pixels[i];
            const g = pixels[i+1];
            const b = pixels[i+2];
            const gray = 0.299 * r + 0.587 * g + 0.114 * b;
            
            let newVal = (gray - 128) * 2.0 + 128;
            newVal = Math.max(0, Math.min(255, newVal));
            
            pixels[i] = newVal;
            pixels[i+1] = newVal;
            pixels[i+2] = newVal;
        }
        ctx.putImageData(imgData, 0, 0);
        
        try {
            document.getElementById('ocr-status').innerText = 'Lendo placa...';
            const { data: { text } } = await ocrWorker.recognize(canvas);
            console.log("OCR Lido:", text);
            
            const cleanedText = text.toUpperCase().replace(/[^A-Z0-9]/g, '');
            
            const selectElement = document.getElementById('modal_vehicle_id');
            let bestMatch = null;
            let bestDistance = 999;
            
            if (selectElement) {
                for (let option of selectElement.options) {
                    const plate = option.getAttribute('data-plate');
                    if (plate) {
                        const cleanPlate = plate.toUpperCase().replace(/[^A-Z0-9]/g, '');
                        
                        if (cleanedText.includes(cleanPlate)) {
                            bestMatch = option;
                            bestDistance = 0;
                            break;
                        }
                        
                        if (cleanedText.length >= 7) {
                            for (let start = 0; start <= cleanedText.length - 7; start++) {
                                const segment = cleanedText.substring(start, start + 7);
                                const dist = levenshteinDistance(segment, cleanPlate);
                                if (dist < bestDistance) {
                                    bestDistance = dist;
                                    bestMatch = option;
                                }
                            }
                        } else if (cleanedText.length > 4) {
                            const dist = levenshteinDistance(cleanedText, cleanPlate);
                            if (dist < bestDistance) {
                                    bestDistance = dist;
                                    bestMatch = option;
                            }
                        }
                    }
                }
            }
            
            if (bestMatch && bestDistance <= 2) {
                const plateMatched = bestMatch.getAttribute('data-plate');
                console.log(`Veículo identificado via Levenshtein (distância: ${bestDistance}): ${plateMatched}`);
                selectElement.value = bestMatch.value;
                selectElement.dispatchEvent(new Event('change'));
                
                if (typeof showToast === "function") {
                    showToast(`Veículo identificado: ${plateMatched}!`, "success");
                } else {
                    alert(`Veículo identificado: ${plateMatched}!`);
                }
                closeOCRScanner();
                return;
            }
        } catch (err) {
            console.error("Erro no processamento de frame OCR:", err);
        }
    }
    
    if (isScanning) {
        document.getElementById('ocr-status').innerText = 'Enquadre a placa';
        setTimeout(scanLoop, 800);
    }
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeOCRScanner();
});
