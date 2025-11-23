document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const qrForm = document.getElementById('qr-form');
    const qrInput = document.getElementById('qr-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const btnText = document.querySelector('.btn-text');
    const btnLoading = document.querySelector('.btn-loading');
    const resultContainer = document.getElementById('result-container');
    const scanCountEl = document.getElementById('scan-count');

    // State
    let scanCount = parseInt(localStorage.getItem('scanCount') || '0');
    updateScanCount();

    // Form Submit Handler
    qrForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const qrData = qrInput.value.trim();
        if (!qrData) return;

        // Set loading state
        setLoading(true);
        resultContainer.style.display = 'none';
        resultContainer.innerHTML = '';

        try {
            const response = await fetch('/api/v1/analyze/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: qrData,
                    client_app: 'web-dashboard'
                })
            });

            if (!response.ok) {
                throw new Error('Analiz servisine ulaşılamadı. Lütfen tekrar deneyin.');
            }

            const data = await response.json();

            // Increment scan count
            scanCount++;
            updateScanCount();
            localStorage.setItem('scanCount', scanCount.toString());

            // Display results with animation delay
            setTimeout(() => {
                displayResults(data);
            }, 300);

        } catch (error) {
            console.error('Analysis error:', error);
            showError(error.message);
        } finally {
            setLoading(false);
        }
    });

    // Set Loading State
    function setLoading(isLoading) {
        analyzeBtn.disabled = isLoading;
        analyzeBtn.classList.toggle('loading', isLoading);
    }

    // Update Scan Count
    function updateScanCount() {
        scanCountEl.textContent = scanCount;
        scanCountEl.style.animation = 'none';
        setTimeout(() => {
            scanCountEl.style.animation = 'countUp 0.5s ease-out';
        }, 10);
    }

    // Display Results
    function displayResults(data) {
        // Map v1 API response to frontend format
        const verdict = mapRiskLevelToVerdict(data.risk_level || 'low');
        const score = data.risk_score || 0;
        const reasons = data.reasons || [];

        const verdictClass = verdict; // safe, suspicious, malicious
        const verdictIcon = getVerdictIcon(verdict);
        const verdictLabel = getVerdictLabel(verdict);

        const html = `
            <div class="result-card ${verdictClass}">
                <div class="result-header">
                    <div class="verdict-badge">
                        <div class="verdict-icon">
                            <i class="${verdictIcon}"></i>
                        </div>
                        <div class="verdict-text">
                            <h2>${verdictLabel}</h2>
                            <span>Analiz Tamamlandı</span>
                        </div>
                    </div>
                    <div class="risk-score">
                        <span class="score-number">${score}</span>
                        <span class="score-label">Risk Skoru</span>
                    </div>
                </div>
                <div class="result-details">
                    <h3>Tespit Edilen Bulgular</h3>
                    ${generateDetailsList(reasons, verdict)}
                </div>
            </div>
        `;

        resultContainer.innerHTML = html;
        resultContainer.style.display = 'block';

        // Scroll to results
        setTimeout(() => {
            resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    // Map v1 API risk_level to frontend verdict
    function mapRiskLevelToVerdict(riskLevel) {
        const mapping = {
            'low': 'safe',
            'medium': 'suspicious',
            'high': 'malicious'
        };
        return mapping[riskLevel] || 'suspicious';
    }

    // Generate Details List
    function generateDetailsList(reasons, verdict) {
        if (!reasons || reasons.length === 0) {
            return `
                <div class="detail-item">
                    <i class="fa-solid fa-circle-check" style="color: var(--accent-success)"></i>
                    <span>Herhangi bir tehdit tespit edilmedi. QR kod güvenli görünüyor.</span>
                </div>
            `;
        }

        return reasons.map(reason => {
            const { icon, color } = getDetailIcon(verdict);
            return `
                <div class="detail-item">
                    <i class="fa-solid ${icon}" style="color: ${color}"></i>
                    <span>${reason}</span>
                </div>
            `;
        }).join('');
    }

    // Get Verdict Icon
    function getVerdictIcon(verdict) {
        const icons = {
            'safe': 'fa-solid fa-shield-check',
            'suspicious': 'fa-solid fa-triangle-exclamation',
            'malicious': 'fa-solid fa-skull-crossbones'
        };
        return icons[verdict] || 'fa-solid fa-circle-question';
    }

    // Get Verdict Label
    function getVerdictLabel(verdict) {
        const labels = {
            'safe': 'GÜVENLİ',
            'suspicious': 'ŞÜPHELİ',
            'malicious': 'TEHLİKELİ'
        };
        return labels[verdict] || verdict.toUpperCase();
    }

    // Get Detail Icon
    function getDetailIcon(verdict) {
        const iconMap = {
            'safe': { icon: 'fa-check-circle', color: 'var(--accent-success)' },
            'suspicious': { icon: 'fa-exclamation-triangle', color: 'var(--accent-warning)' },
            'malicious': { icon: 'fa-times-circle', color: 'var(--accent-danger)' }
        };
        return iconMap[verdict] || { icon: 'fa-info-circle', color: 'var(--text-secondary)' };
    }

    // Show Error
    function showError(message) {
        const html = `
            <div class="result-card malicious">
                <div class="result-header">
                    <div class="verdict-badge">
                        <div class="verdict-icon">
                            <i class="fa-solid fa-circle-exclamation"></i>
                        </div>
                        <div class="verdict-text">
                            <h2>HATA</h2>
                            <span>Bir sorun oluştu</span>
                        </div>
                    </div>
                </div>
                <div class="result-details">
                    <div class="detail-item">
                        <i class="fa-solid fa-bug" style="color: var(--accent-danger)"></i>
                        <span>${message}</span>
                    </div>
                </div>
            </div>
        `;

        resultContainer.innerHTML = html;
        resultContainer.style.display = 'block';
    }

    // Input animation on focus
    qrInput.addEventListener('focus', () => {
        qrInput.parentElement.style.transform = 'scale(1.01)';
    });

    qrInput.addEventListener('blur', () => {
        qrInput.parentElement.style.transform = 'scale(1)';
    });

    // Add CSS animation for count
    const style = document.createElement('style');
    style.textContent = `
        @keyframes countUp {
            0% { transform: scale(0.8); opacity: 0; }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); opacity: 1; }
        }
    `;
    document.head.appendChild(style);
});
