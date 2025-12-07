const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // File System Operations
  selectFile: () => ipcRenderer.invoke('select-file'),
  selectFolder: () => ipcRenderer.invoke('select-folder'),
  checkPathExists: (path) => ipcRenderer.invoke('check-path-exists', path),
  
  // Notification Handlers
  showError: (message) => ipcRenderer.invoke('show-error', message),
  showSuccess: (title, message) => ipcRenderer.invoke('show-success', title, message),
  
  // --- THIS WAS MISSING AND CAUSED YOUR ERROR ---
  showInfo: (title, message) => ipcRenderer.invoke('show-info', title, message),
  // --------------------------------------------

  // Window Management
  openBlockchainViewer: () => ipcRenderer.invoke('open-blockchain-viewer')
});