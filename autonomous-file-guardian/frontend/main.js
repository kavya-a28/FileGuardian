const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require('electron');
const path = require('path');
const fs = require('fs');
app.disableHardwareAcceleration();
let mainWindow;
let blockchainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    },
    frame: true,
    backgroundColor: '#0f172a',
    icon: path.join(__dirname, 'icon.png')
  });

  mainWindow.loadFile('src/index.html');
  
  // Create application menu
  createApplicationMenu();
  
  // Open DevTools in development
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createBlockchainWindow() {
  // Check if window already exists
  if (blockchainWindow && !blockchainWindow.isDestroyed()) {
    blockchainWindow.focus();
    return;
  }

  blockchainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 600,
    title: 'FileGuardian Blockchain Explorer',
    backgroundColor: '#0f172a',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false // Allow CORS for localhost
    }
  });

  // Load the blockchain viewer
  const blockchainViewerPath = path.join(__dirname, 'src', 'blockchain-viewer.html');
  
  // Check if file exists
  if (fs.existsSync(blockchainViewerPath)) {
    blockchainWindow.loadFile(blockchainViewerPath);
  } else {
    // Fallback: try root directory
    const fallbackPath = path.join(__dirname, 'blockchain-viewer.html');
    if (fs.existsSync(fallbackPath)) {
      blockchainWindow.loadFile(fallbackPath);
    } else {
      dialog.showErrorBox('File Not Found', 
        'blockchain-viewer.html not found!\n\n' +
        'Expected location:\n' +
        blockchainViewerPath + '\n\nor\n' + fallbackPath
      );
      blockchainWindow.close();
      blockchainWindow = null;
      return;
    }
  }

  // Open DevTools in development
  if (process.argv.includes('--dev')) {
    blockchainWindow.webContents.openDevTools();
  }

  // Handle window closed
  blockchainWindow.on('closed', () => {
    blockchainWindow = null;
  });
}

function createApplicationMenu() {
  const isMac = process.platform === 'darwin';

  const menuTemplate = [
    // App Menu (Mac only)
    ...(isMac ? [{
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' }
      ]
    }] : []),

    // File Menu
    {
      label: 'File',
      submenu: [
        {
          label: 'Encrypt File',
          accelerator: 'CmdOrCtrl+E',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'encrypt');
              mainWindow.focus();
            }
          }
        },
        {
          label: 'Encrypt Folder',
          accelerator: 'CmdOrCtrl+Shift+E',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'encrypt');
              mainWindow.focus();
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Settings',
          accelerator: 'CmdOrCtrl+,',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'settings');
              mainWindow.focus();
            }
          }
        },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit' }
      ]
    },

    // View Menu
    {
      label: 'View',
      submenu: [
        {
          label: 'Protected Files',
          accelerator: 'CmdOrCtrl+F',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'files');
              mainWindow.focus();
            }
          }
        },
        {
          label: 'Activity Logs',
          accelerator: 'CmdOrCtrl+L',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'logs');
              mainWindow.focus();
            }
          }
        },
        {
          label: 'Dashboard',
          accelerator: 'CmdOrCtrl+D',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.send('switch-view', 'dashboard');
              mainWindow.focus();
            }
          }
        },
        { type: 'separator' },
        {
          label: '🔗 Blockchain Explorer',
          accelerator: 'CmdOrCtrl+B',
          click: createBlockchainWindow
        },
        { type: 'separator' },
        {
          label: 'Reload',
          accelerator: 'CmdOrCtrl+R',
          click: () => {
            if (mainWindow) {
              mainWindow.reload();
            }
          }
        },
        {
          label: 'Force Reload',
          accelerator: 'CmdOrCtrl+Shift+R',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.reloadIgnoringCache();
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Toggle Developer Tools',
          accelerator: isMac ? 'Alt+Command+I' : 'Ctrl+Shift+I',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.toggleDevTools();
            }
          }
        },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },

    // Tools Menu
    {
      label: 'Tools',
      submenu: [
        {
          label: 'Check Blockchain Status',
          click: async () => {
            try {
              const response = await fetch('http://localhost:8000/api/settings/');
              const data = await response.json();
              
              const status = data.blockchain_enabled ? '✅ Connected' : '❌ Not Connected';
              const message = data.blockchain_enabled ? 
                'Connected to Ethereum blockchain\nSmart contract deployed and operational\nAll file operations are being logged to blockchain' :
                'Blockchain features are currently disabled\n\nTo enable:\n1. Start Ganache: ganache-cli -p 8545\n2. Deploy contract: python deploy_contract.py\n3. Restart application';
              
              dialog.showMessageBox(mainWindow, {
                type: data.blockchain_enabled ? 'info' : 'warning',
                title: 'Blockchain Status',
                message: `Blockchain: ${status}`,
                detail: message,
                buttons: ['OK']
              });
            } catch (error) {
              dialog.showErrorBox('Connection Error', 
                'Cannot connect to backend server!\n\n' +
                'Make sure Django is running:\n' +
                'cd backend\n' +
                'python manage.py runserver\n\n' +
                'Error: ' + error.message
              );
            }
          }
        },
        {
          label: 'Open Ganache Console',
          click: () => {
            shell.openExternal('http://localhost:8545');
          }
        },
        {
          label: 'View Backend Logs',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'Backend Logs',
              message: 'Backend server logs are displayed in the terminal where you started Django.',
              detail: 'To view logs, check the terminal/console where you ran:\npython manage.py runserver',
              buttons: ['OK']
            });
          }
        },
        { type: 'separator' },
        {
          label: 'Clear Cache',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.session.clearCache();
              dialog.showMessageBox(mainWindow, {
                type: 'info',
                title: 'Cache Cleared',
                message: 'Application cache has been cleared successfully.',
                buttons: ['OK']
              });
            }
          }
        }
      ]
    },

    // Window Menu
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        ...(isMac ? [
          { type: 'separator' },
          { role: 'front' },
          { type: 'separator' },
          { role: 'window' }
        ] : [
          { role: 'close' }
        ])
      ]
    },

    // Help Menu
    {
      label: 'Help',
      submenu: [
        {
          label: 'About FileGuardian',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About FileGuardian',
              message: 'FileGuardian v1.0',
              detail: 
                'Autonomous File Protection System with Blockchain Integration\n\n' +
                '🔒 Features:\n' +
                '• Military-grade AES-256 encryption\n' +
                '• Blockchain registration and verification\n' +
                '• Device-based access control\n' +
                '• Canary token tracking for unauthorized access\n' +
                '• Real-time file monitoring\n' +
                '• Immutable audit trails\n\n' +
                '© 2025 FileGuardian Project',
              buttons: ['OK']
            });
          }
        },
        {
          label: 'Documentation',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'Documentation',
              message: 'FileGuardian Documentation',
              detail: 
                'Quick Start Guide:\n\n' +
                '1. ENCRYPT: Select a file/folder, enter master key, encrypt\n' +
                '2. MONITOR: View protected files and activity logs\n' +
                '3. DECRYPT: Enter master key to access encrypted files\n' +
                '4. BLOCKCHAIN: View immutable records in Blockchain Explorer\n\n' +
                'For detailed documentation, check the README.md file.',
              buttons: ['OK']
            });
          }
        },
        {
          label: 'Keyboard Shortcuts',
          click: () => {
            const shortcuts = isMac ? 
              'Cmd+E - Encrypt File\n' +
              'Cmd+F - Protected Files\n' +
              'Cmd+L - Activity Logs\n' +
              'Cmd+D - Dashboard\n' +
              'Cmd+B - Blockchain Explorer\n' +
              'Cmd+, - Settings\n' +
              'Cmd+R - Reload\n' +
              'Alt+Cmd+I - Developer Tools' :
              'Ctrl+E - Encrypt File\n' +
              'Ctrl+F - Protected Files\n' +
              'Ctrl+L - Activity Logs\n' +
              'Ctrl+D - Dashboard\n' +
              'Ctrl+B - Blockchain Explorer\n' +
              'Ctrl+, - Settings\n' +
              'Ctrl+R - Reload\n' +
              'Ctrl+Shift+I - Developer Tools';

            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'Keyboard Shortcuts',
              message: 'Available Shortcuts',
              detail: shortcuts,
              buttons: ['OK']
            });
          }
        },
        { type: 'separator' },
        {
          label: 'Check for Updates',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'Check for Updates',
              message: 'You are using the latest version',
              detail: 'FileGuardian v1.0\n\nNo updates available at this time.',
              buttons: ['OK']
            });
          }
        },
        { type: 'separator' },
        {
          label: 'Report an Issue',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'Report an Issue',
              message: 'Found a bug or have a suggestion?',
              detail: 'Please report issues on our GitHub repository or contact the development team.',
              buttons: ['OK']
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);
}

// Application ready event
app.whenReady().then(() => {
  createWindow();
  
  // Show welcome message on first run
  const welcomeShown = app.getPath('userData') + '/welcome-shown';
  if (!fs.existsSync(welcomeShown)) {
    setTimeout(() => {
      dialog.showMessageBox(mainWindow, {
        type: 'info',
        title: 'Welcome to FileGuardian',
        message: 'Welcome to FileGuardian! 🛡️',
        detail: 
          'Your files are now protected with military-grade encryption and blockchain security.\n\n' +
          'Quick Tips:\n' +
          '• Use Ctrl+B (Cmd+B on Mac) to open Blockchain Explorer\n' +
          '• All file operations are logged to blockchain\n' +
          '• Check Tools > Blockchain Status to verify connection\n\n' +
          'Get started by encrypting your first file!',
        buttons: ['Get Started']
      });
      fs.writeFileSync(welcomeShown, 'true');
    }, 1000);
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC Handlers
ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    title: 'Select File to Encrypt',
    buttonLabel: 'Select File'
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return { 
      success: true, 
      path: result.filePaths[0],
      type: 'file'
    };
  }
  return { success: false };
});

ipcMain.handle('select-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Folder to Encrypt',
    buttonLabel: 'Select Folder'
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return { 
      success: true, 
      path: result.filePaths[0],
      type: 'folder'
    };
  }
  return { success: false };
});

ipcMain.handle('check-path-exists', async (event, filePath) => {
  try {
    return fs.existsSync(filePath);
  } catch (error) {
    console.error('Error checking path:', error);
    return false;
  }
});

ipcMain.handle('show-error', async (event, message) => {
  dialog.showErrorBox('Error', message);
});

ipcMain.handle('show-success', async (event, title, message) => {
  await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: title,
    message: message,
    buttons: ['OK']
  });
});

ipcMain.handle('show-info', async (event, title, message) => {
  await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: title,
    message: message,
    buttons: ['OK']
  });
});

ipcMain.handle('open-blockchain-viewer', async () => {
  createBlockchainWindow();
});

// Handle opening external links
app.on('web-contents-created', (event, contents) => {
  contents.setWindowOpenHandler(({ url }) => {
    // Open external links in default browser
    if (url.startsWith('http') || url.startsWith('https')) {
      shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });
});

// Log application info on startup
console.log('==========================================');
console.log('FileGuardian Application Started');
console.log('Version: 1.0.0');
console.log('Electron:', process.versions.electron);
console.log('Node:', process.versions.node);
console.log('Chrome:', process.versions.chrome);
console.log('==========================================');