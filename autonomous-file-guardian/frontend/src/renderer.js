// Configuration
const API_BASE_URL = 'http://localhost:8000/api';

// State
let currentView = 'encrypt';
let selectedPath = null;
let selectedType = null;
let currentFileForDecryption = null;
let currentLogFilter = 'all';
let currentFileFilter = 'active';
let hasCanaryConfigured = false;
let has2FAConfigured = false;
let temp2FASecret = null; // Used during setup

// --- VAULT STATE & ELEMENTS ---
let isVaultSetup = false;
const vaultScreen = document.getElementById('vault-lock-screen');
const vaultTitle = document.getElementById('vault-title');
const vaultDesc = document.getElementById('vault-desc');
const vaultBtn = document.getElementById('btn-unlock-vault');
const vaultInput = document.getElementById('vault-password');
const vaultError = document.getElementById('vault-error');

// Utility Functions
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 4000);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

async function apiRequest(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            }
        };
        
        if (data && method !== 'GET') {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'API request failed');
        }
        
        return result;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ---------------------------------------------------------
// --- VAULT LOGIC (THE GATEKEEPER) ------------------------
// ---------------------------------------------------------

async function checkVaultStatus() {
    try {
        const result = await apiRequest('/vault/status/');
        isVaultSetup = result.is_setup;
        
        if (!result.is_setup) {
            // Case 1: First Time Setup
            vaultScreen.style.display = 'flex';
            vaultTitle.textContent = "Welcome to File Guardian";
            vaultDesc.textContent = "Create a Master Password to encrypt your vault database.";
            vaultBtn.textContent = "Create Vault";
            vaultInput.placeholder = "Choose a strong password";
        } else if (result.is_locked) {
            // Case 2: Locked
            vaultScreen.style.display = 'flex';
            vaultTitle.textContent = "Vault Locked";
            vaultDesc.textContent = "Enter Master Password to access your files.";
            vaultBtn.textContent = "Unlock Vault";
            vaultInput.placeholder = "Master Password";
        } else {
            // Case 3: Unlocked
            vaultScreen.style.display = 'none';
            // Safe to load sensitive data now
            initializeApplication(); 
        }
    } catch (error) {
        console.error("Vault check failed:", error);
        // If API is down, we can't do anything, but let's try connecting again
        setTimeout(checkVaultStatus, 5000);
    }
}

// Handle Unlock/Setup Button Click
if (vaultBtn) {
    vaultBtn.addEventListener('click', async () => {
        const password = vaultInput.value;
        if (!password) {
            vaultError.textContent = "Password is required";
            vaultError.style.display = 'block';
            return;
        }
        
        vaultBtn.disabled = true;
        vaultError.style.display = 'none';
        
        try {
            if (!isVaultSetup) {
                // Perform Setup
                if (password.length < 8) throw new Error("Password must be at least 8 characters");
                await apiRequest('/vault/setup/', 'POST', { password });
                showToast('Vault created successfully!', 'success');
                location.reload(); // Reload to enter clean state
            } else {
                // Perform Unlock
                await apiRequest('/vault/unlock/', 'POST', { password });
                vaultScreen.style.display = 'none';
                vaultInput.value = ''; // Clear password from memory
                initializeApplication();
            }
        } catch (error) {
            vaultError.textContent = error.message || "Operation failed";
            vaultError.style.display = 'block';
            vaultBtn.disabled = false;
        }
    });
}

// Handle Manual Lock Button
document.getElementById('btn-lock-app')?.addEventListener('click', async () => {
    try {
        await apiRequest('/vault/lock/', 'POST');
        location.reload(); // Reload page to force lock screen
    } catch (error) {
        console.error("Lock failed", error);
    }
});

function initializeApplication() {
    loadSettings();
    checkBackendConnection();
    // Load initial view data
    if (currentView === 'files') loadFiles();
    if (currentView === 'logs') { loadLogs(); updateStats(); }
}

// ---------------------------------------------------------
// --- END VAULT LOGIC -------------------------------------
// ---------------------------------------------------------


// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        // Skip if it's the lock button
        if(item.id === 'btn-lock-app') return;
        
        const view = item.getAttribute('data-view');
        if (view) switchView(view);
    });
});

function switchView(view) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-view') === view) {
            item.classList.add('active');
        }
    });
    
    document.querySelectorAll('.view').forEach(v => {
        v.classList.remove('active');
    });
    
    const viewElement = document.getElementById(`${view}-view`);
    if (viewElement) {
        viewElement.classList.add('active');
    }
    
    currentView = view;
    
    if (view === 'files') {
        loadFiles();
    } else if (view === 'logs') {
        loadLogs();
        updateStats();
    } else if (view === 'settings') {
        loadSettings();
    } else if (view === 'recovery') {
        const recoveryList = document.getElementById('recovery-list');
        if (recoveryList) {
            recoveryList.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
                <h3>Scan for Lost Files</h3>
                <p>Click "Scan Blockchain" to compare local data with the immutable ledger.</p>
            </div>`;
        }
    }
}

// Load Settings
async function loadSettings() {
    try {
        const result = await apiRequest('/settings/');
        hasCanaryConfigured = result.has_canary_configured;
        has2FAConfigured = result.has_2fa_configured;
        
        const tokenInput = document.getElementById('canary-token-url');
        if(tokenInput) tokenInput.value = result.default_canary_token || '';
        
        updateCanaryStatus();
        update2FAStatus();
        loadCanaryStats();
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

function updateCanaryStatus() {
    const statusEl = document.getElementById('canary-status');
    const useCanaryCheckbox = document.getElementById('use-canary');
    
    if (hasCanaryConfigured) {
        statusEl.textContent = '✅ Canary token configured and will be embedded';
        statusEl.style.color = 'var(--success)';
        useCanaryCheckbox.disabled = false;
    } else {
        statusEl.textContent = '⚠️ No canary token configured. Go to Settings to add one.';
        statusEl.style.color = 'var(--warning)';
        useCanaryCheckbox.disabled = true;
        useCanaryCheckbox.checked = false;
    }
}

function update2FAStatus() {
    const statusMsg = document.getElementById('2fa-status-msg');
    const setupBtn = document.getElementById('btn-setup-2fa');
    const qrDisplay = document.getElementById('qr-display');
    
    if (has2FAConfigured) {
        if (statusMsg) statusMsg.innerHTML = '<span style="color: var(--success); font-weight: bold;">✅ 2FA is Active and Protecting Files</span>';
        if (setupBtn) setupBtn.style.display = 'none';
        if (qrDisplay) qrDisplay.style.display = 'none';
    } else {
        if (statusMsg) statusMsg.textContent = '2FA is currently disabled.';
        if (setupBtn) setupBtn.style.display = 'inline-block';
    }

    const checkbox2fa = document.getElementById('use-2fa');
    const text2fa = document.getElementById('2fa-status-text');
    
    if (checkbox2fa && text2fa) {
        if (has2FAConfigured) {
            checkbox2fa.disabled = false;
            text2fa.textContent = 'Adds an extra layer of security (Requires Code)';
            text2fa.style.color = 'var(--text-muted)';
        } else {
            checkbox2fa.disabled = true;
            checkbox2fa.checked = false;
            text2fa.textContent = '⚠️ Enable 2FA in Settings first';
            text2fa.style.color = 'var(--warning)';
        }
    }
}

async function loadCanaryStats() {
    try {
        const result = await apiRequest('/canary/list/');
        const statsDiv = document.getElementById('canary-stats');
        
        if (result.tokens.length === 0) {
            statsDiv.innerHTML = '<p style="color: var(--text-muted); text-align: center; padding: 24px;">No canary tokens configured yet</p>';
            return;
        }
        
        statsDiv.innerHTML = '<div class="stats-grid">' + result.tokens.map(token => `
            <div class="stat-card">
                <div class="stat-label">Token ID: ${token.token_id}</div>
                <div class="stat-value">${token.trigger_count}</div>
                <div class="stat-label">Times Triggered</div>
                ${token.last_triggered ? `<small style="margin-top: 8px; display: block;">Last: ${formatDate(token.last_triggered)}</small>` : '<small style="margin-top: 8px; display: block;">Never triggered</small>'}
            </div>
        `).join('') + '</div>';
    } catch (error) {
        const statsDiv = document.getElementById('canary-stats');
        if(statsDiv) statsDiv.innerHTML = '<p style="color: var(--error); text-align: center; padding: 24px;">Failed to load statistics</p>';
    }
}

// 2FA Setup
document.getElementById('btn-setup-2fa')?.addEventListener('click', async () => {
    try {
        const result = await apiRequest('/auth/setup-2fa/', 'POST');
        if (result.qr_code) {
            document.getElementById('qr-image').src = result.qr_code;
            document.getElementById('qr-display').style.display = 'block';
            document.getElementById('btn-setup-2fa').style.display = 'none';
            temp2FASecret = result.secret;
        }
    } catch (error) {
        showToast(error.message, 'error');
    }
});

document.getElementById('btn-confirm-2fa')?.addEventListener('click', async () => {
    const code = document.getElementById('verify-2fa-code').value;
    if (!code) return showToast('Please enter the code', 'warning');

    try {
        const result = await apiRequest('/auth/confirm-2fa/', 'POST', {
            secret: temp2FASecret,
            code: code
        });
        if (result.success) {
            showToast('✅ 2FA Enabled Successfully!', 'success');
            has2FAConfigured = true;
            update2FAStatus();
        }
    } catch (error) {
        showToast(`❌ Verification failed: ${error.message}`, 'error');
    }
});

// Save Canary
document.getElementById('btn-save-canary')?.addEventListener('click', async () => {
    const tokenUrl = document.getElementById('canary-token-url').value.trim();
    if (!tokenUrl) return showToast('Please enter a URL', 'warning');
    
    try {
        await apiRequest('/canary/create/', 'POST', { token_url: tokenUrl, description: 'Default canary token' });
        await apiRequest('/settings/canary/', 'POST', { token_url: tokenUrl });
        showToast('✅ Canary token saved!', 'success');
        hasCanaryConfigured = true;
        updateCanaryStatus();
        loadCanaryStats();
    } catch (error) {
        showToast(`❌ Failed: ${error.message}`, 'error');
    }
});

// Encrypt
document.getElementById('btn-select-file').addEventListener('click', async () => {
    const result = await window.electronAPI.selectFile();
    if (result.success) {
        selectedPath = result.path;
        selectedType = 'file';
        showEncryptForm();
    }
});

document.getElementById('btn-select-folder').addEventListener('click', async () => {
    const result = await window.electronAPI.selectFolder();
    if (result.success) {
        selectedPath = result.path;
        selectedType = 'folder';
        showEncryptForm();
    }
});

function showEncryptForm() {
    document.querySelector('.selection-cards').style.display = 'none';
    document.getElementById('encrypt-form').style.display = 'block';
    document.getElementById('selected-path').textContent = selectedPath;
    updateCanaryStatus();
    update2FAStatus();
}

document.getElementById('btn-cancel').addEventListener('click', resetEncryptForm);

function resetEncryptForm() {
    document.querySelector('.selection-cards').style.display = 'grid';
    document.getElementById('encrypt-form').style.display = 'none';
    document.getElementById('master-key').value = '';
    document.getElementById('use-canary').checked = false;
    if(document.getElementById('use-2fa')) document.getElementById('use-2fa').checked = false;
    selectedPath = null;
    selectedType = null;
}

document.getElementById('btn-encrypt').addEventListener('click', async () => {
    const masterKey = document.getElementById('master-key').value;
    const useCanary = document.getElementById('use-canary').checked;
    const use2fa = document.getElementById('use-2fa') ? document.getElementById('use-2fa').checked : false;
    
    if (!masterKey || masterKey.length < 8) return showToast('Master key must be 8+ chars', 'error');
    
    try {
        document.getElementById('encrypt-form').style.display = 'none';
        document.getElementById('progress-container').style.display = 'block';
        
        const result = await apiRequest('/encrypt/', 'POST', {
            file_path: selectedPath,
            master_key: masterKey,
            file_type: selectedType,
            use_canary: useCanary,
            requires_2fa: use2fa
        });
        
        if (result.success) {
            showToast(`✅ Encrypted Successfully`, 'success');
            await window.electronAPI.showSuccess('Success', result.message + '\n\nFile location: ' + result.encrypted_path);
            resetEncryptForm();
            document.getElementById('progress-container').style.display = 'none';
        }
    } catch (error) {
        document.getElementById('progress-container').style.display = 'none';
        document.getElementById('encrypt-form').style.display = 'block';
        showToast(`❌ Failed: ${error.message}`, 'error');
        await window.electronAPI.showError(`Encryption failed: ${error.message}`);
    }
});

// Files View
document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFileFilter = btn.getAttribute('data-filter');
        loadFiles();
    });
});

async function loadFiles() {
    const filesList = document.getElementById('files-list');
    filesList.innerHTML = '<div class="loading">Loading files...</div>';
    
    try {
        const includeDeleted = currentFileFilter === 'deleted' || currentFileFilter === 'all';
        const result = await apiRequest(`/files/?include_deleted=${includeDeleted}`);
        let files = result.files;
        
        if (currentFileFilter === 'active') files = files.filter(f => !f.is_deleted_by_user);
        else if (currentFileFilter === 'deleted') files = files.filter(f => f.is_deleted_by_user);
        
        if (files.length === 0) {
            filesList.innerHTML = `<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path></svg><h3>No files found</h3></div>`;
            return;
        }
        
        filesList.innerHTML = files.map(file => `
            <div class="file-card ${file.is_deleted_by_user ? 'file-deleted' : (!file.exists ? 'file-missing' : '')}">
                <div class="file-header">
                    <div class="file-info">
                        <div class="file-icon ${!file.exists ? 'icon-warning' : ''}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                ${file.file_type === 'folder' ? '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>' : '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>'}
                            </svg>
                        </div>
                        <div>
                            <div class="file-name">${file.file_name}</div>
                            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                                ${file.file_type.toUpperCase()} • ${file.is_deleted_by_user ? '🗑️ Deleted' : (file.exists ? '✓ Protected' : '⚠️ Missing')}
                                ${file.requires_2fa ? ' • 🔒 2FA' : ''}
                            </div>
                        </div>
                    </div>
                    <div class="file-actions">
                        ${file.is_deleted_by_user ? `
                            <button class="btn-icon btn-success" onclick="restoreFile(${file.id})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path><path d="M21 3v5h-5"></path></svg></button>
                        ` : file.exists ? `
                            <button class="btn-icon" onclick="verifyFileIntegrity(${file.id})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg></button>
                            <button class="btn-icon" onclick="showFileLocation(${file.id})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg></button>
                            <button class="btn-icon btn-success" onclick="decryptFile(${file.id}, '${file.file_name}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path></svg></button>
                        ` : ''}
                        <button class="btn-icon btn-danger" onclick="deleteFile(${file.id})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        filesList.innerHTML = '<div class="loading">Error loading files</div>';
    }
}

// Global Window Functions
window.verifyFileIntegrity = async function(fileId) {
    showToast('⏳ Verifying...', 'info');
    try {
        const result = await apiRequest(`/files/${fileId}/verify-integrity/`, 'POST');
        if (result.is_valid) {
            showToast('✅ Verified!', 'success');
            await window.electronAPI.showSuccess('Integrity Check', 'Matches Blockchain record.');
        } else {
            await window.electronAPI.showError('🚨 TAMPERING DETECTED!');
        }
    } catch (error) {
        showToast(`❌ Failed: ${error.message}`, 'error');
    }
};

window.restoreFile = async function(fileId) {
    if (!confirm('Restore from backup?')) return;
    try {
        await apiRequest(`/files/${fileId}/restore/`, 'POST');
        showToast('✅ Restored!', 'success');
        loadFiles();
    } catch (error) {
        showToast(`❌ Failed: ${error.message}`, 'error');
    }
};

window.showFileLocation = async function(fileId) {
    try {
        const result = await apiRequest(`/files/${fileId}/location/`);
        await window.electronAPI.showInfo('Location', result.location);
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
};

window.deleteFile = async function(fileId) {
    if (!confirm('Stop monitoring?')) return;
    try {
        await apiRequest(`/files/${fileId}/delete/`, 'DELETE');
        showToast('✅ Stopped', 'success');
        loadFiles();
    } catch (error) {
        showToast(`❌ Error: ${error.message}`, 'error');
    }
};

window.decryptFile = function(fileId, fileName) {
    currentFileForDecryption = fileId;
    document.getElementById('decrypt-filename').textContent = fileName;
    document.getElementById('decrypt-modal').classList.add('active');
    document.getElementById('decrypt-master-key').value = '';
    
    // Reset 2FA
    const codeContainer = document.getElementById('2fa-input-container');
    if(codeContainer) codeContainer.style.display = 'none';
    const codeInput = document.getElementById('decrypt-2fa-code');
    if(codeInput) codeInput.value = '';
    
    document.getElementById('device-verification').style.display = 'none';
    document.getElementById('decrypt-master-key').focus();
};

document.getElementById('modal-close').addEventListener('click', () => {
    document.getElementById('decrypt-modal').classList.remove('active');
});
document.getElementById('modal-cancel').addEventListener('click', () => {
    document.getElementById('decrypt-modal').classList.remove('active');
});

document.getElementById('btn-decrypt').addEventListener('click', async () => {
    const masterKey = document.getElementById('decrypt-master-key').value;
    const totpCode = document.getElementById('decrypt-2fa-code') ? document.getElementById('decrypt-2fa-code').value : '';
    
    if (!masterKey) return showToast('Enter master key', 'error');
    
    try {
        const verifyDiv = document.getElementById('device-verification');
        verifyDiv.style.display = 'block';
        verifyDiv.innerHTML = `<div class="verification-status"><div class="spinner-small"></div><span>Decrypting...</span></div>`;
        
        const result = await apiRequest('/decrypt/', 'POST', {
            encrypted_id: currentFileForDecryption,
            master_key: masterKey,
            totp_code: totpCode
        });
        
        if (result.success) {
            showToast('✅ Decrypted', 'success');
            await window.electronAPI.showSuccess('Success', result.message);
            document.getElementById('decrypt-modal').classList.remove('active');
            loadFiles();
        }
    } catch (error) {
        // Handle 2FA Requirement
        if (error.message.includes('2FA Code Required') || error.message.includes('401')) {
            document.getElementById('device-verification').style.display = 'none';
            const container = document.getElementById('2fa-input-container');
            if (container) {
                container.style.display = 'block';
                document.getElementById('decrypt-2fa-code').focus();
                showToast('🔒 2FA Code Required', 'warning');
            }
            return;
        }
        
        document.getElementById('device-verification').innerHTML = `<span style="color:var(--error)">${error.message}</span>`;
        showToast(`❌ Failed: ${error.message}`, 'error');
    }
});

// Logs & Stats
document.querySelectorAll('[data-severity]').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('[data-severity]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentLogFilter = btn.getAttribute('data-severity');
        loadLogs(currentLogFilter);
    });
});

async function loadLogs(severity = 'all') {
    const logsList = document.getElementById('logs-list');
    logsList.innerHTML = '<div class="loading">Loading logs...</div>';
    try {
        const endpoint = severity === 'all' ? '/logs/' : `/logs/?severity=${severity}`;
        const result = await apiRequest(endpoint);
        if (result.logs.length === 0) {
            logsList.innerHTML = '<div class="empty-state"><h3>No logs</h3></div>';
            return;
        }
        logsList.innerHTML = result.logs.map(log => `
            <div class="log-card severity-${log.severity}">
                <div class="log-header">
                    <div class="log-action"><span>${getActionIcon(log.action)}</span> <span>${formatAction(log.action)}</span></div>
                    <span class="severity-badge severity-${log.severity}">${log.severity.toUpperCase()}</span>
                </div>
                <div class="log-description">${log.description}</div>
                <div class="log-timestamp">📁 ${log.encrypted_file__file_name || 'N/A'} • 🕐 ${formatDate(log.timestamp)}</div>
            </div>
        `).join('');
    } catch (error) {
        logsList.innerHTML = '<div class="loading">Error loading logs</div>';
    }
}
function getActionIcon(action) {
    const icons = { encrypt: '🔒', decrypt: '🔓', access_denied: '🚫', file_deleted: '🗑️', suspicious_activity: '⚠️', canary_triggered: '🕵️', integrity_verified: '✅', integrity_violation: '🚨', '2fa_setup': '🛡️', '2fa_failed': '🛑' };
    return icons[action] || '📝';
}

function formatAction(action) {
    return action.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

async function updateStats() {
    const statsGrid = document.getElementById('stats-grid');
    if (!statsGrid) return;
    try {
        const result = await apiRequest('/dashboard/stats/');
        statsGrid.innerHTML = `
            <div class="stat-card">
                <div class="stat-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                        <polyline points="13 2 13 9 20 9"></polyline>
                    </svg>
                </div>
                <div class="stat-value">${result.total_files}</div>
                <div class="stat-label">Protected Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                </div>
                <div class="stat-value">${result.canary_triggers}</div>
                <div class="stat-label">Canary Triggers</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                </div>
                <div class="stat-value">${result.critical_alerts}</div>
                <div class="stat-label">Critical Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                </div>
                <div class="stat-value">${result.total_files || 0}</div>
                <div class="stat-label">Encrypted Files</div>
            </div>
        `;
    } catch (e) {}
}

// Recovery
document.getElementById('btn-scan-blockchain')?.addEventListener('click', async () => {
    const listEl = document.getElementById('recovery-list');
    listEl.innerHTML = '<div class="loading"><div class="spinner"></div><p>Scanning...</p></div>';
    try {
        const result = await apiRequest('/recovery/scan/');
        if (result.files.length === 0) { 
            listEl.innerHTML = '<div class="empty-state"><h3>No files found</h3></div>'; 
            return; 
        }
        
        let html = '';
        result.files.forEach(f => {
            if(f.name === 'test.txt') return;
            html += `<div class="file-card">
                <div class="recovery-file-info">
                    <div class="recovery-file-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                            <polyline points="13 2 13 9 20 9"></polyline>
                        </svg>
                    </div>
                    <div class="recovery-file-details">
                        <div class="recovery-file-name">${f.name}</div>
                        ${f.status === 'missing' 
                            ? '<span class="recovery-status-badge status-missing">⚠️ Missing from Database</span>' 
                            : '<span class="recovery-status-badge status-safe"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="20 6 9 17 4 12"></polyline></svg>Safe</span>'
                        }
                    </div>
                </div>
                ${f.status === 'missing' 
                    ? `<div class="file-actions">
                        <button class="btn-recover" onclick="performRecovery(${f.blockchain_id}, '${f.ipfs_cid}', '${f.name}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            Recover
                        </button>
                    </div>` 
                    : ''
                }
            </div>`;
        });
        listEl.innerHTML = html || '<div class="empty-state">No files</div>';
    } catch (e) {
        listEl.innerHTML = `<div class="empty-state" style="color:var(--error)">Error: ${e.message}</div>`;
    }
});

window.performRecovery = async function(blockchainId, ipfsCid, fileName) {
    if(!confirm(`Recover "${fileName}"?`)) return;
    try {
        const result = await apiRequest('/recovery/restore/', 'POST', { blockchain_id: blockchainId, ipfs_cid: ipfsCid, file_name: fileName });
        if (result.success) { showToast('✅ Recovered!', 'success'); document.getElementById('btn-scan-blockchain').click(); }
    } catch (e) { showToast(`❌ Error: ${e.message}`, 'error'); }
};

async function checkBackendConnection() {
    try {
        await fetch(`${API_BASE_URL}/files/`);
        document.querySelector('.status-dot').style.background = 'var(--success)';
    } catch (e) {
        document.querySelector('.status-dot').style.background = 'var(--error)';
        showToast('⚠️ Backend Offline', 'warning');
    }
}

// STARTUP: Check Vault Status FIRST
checkVaultStatus();

// Auto-Refresh Logic (Respects Lock Screen)
setInterval(async () => {
    try {
        // Quick lightweight check for lock status
        const res = await fetch(`${API_BASE_URL}/vault/status/`);
        const data = await res.json();
        
        if (data.is_locked && vaultScreen.style.display === 'none') {
            // App was unlocked, but backend locked (e.g. server restart) -> Force Reload
            location.reload(); 
        } else if (!data.is_locked) {
            // Unlocked -> Refresh Data
            if (currentView === 'logs') { loadLogs(currentLogFilter); updateStats(); }
            else if (currentView === 'files') { loadFiles(); }
        }
    } catch (e) {}
}, 15000);