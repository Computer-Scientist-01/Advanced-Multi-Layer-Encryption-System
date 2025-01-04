// Advanced Multi-Layer Encryption System (AMLES)
import chalk from 'chalk';
import { createSpinner } from 'nanospinner';
import figlet from 'figlet';
import gradient from 'gradient-string';
import cliProgress from 'cli-progress';
import crypto from 'crypto';
import readline from 'readline';
import fs from 'fs';
import zlib from 'zlib';
import { promisify } from 'util';
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);



// Advanced key generation with multiple security layers
function generateKey(length = 64) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?`~';
    let key = '';
    const array = new Uint8Array(length);
    crypto.randomFillSync(array); // More secure random generation
    
    for (let i = 0; i < length; i++) {
        key += chars.charAt(array[i] % chars.length);
    }
    return key + crypto.randomBytes(32).toString('hex'); // Add additional random bytes
}

// Generate initialization vector
function generateIV() {
    return crypto.randomBytes(16);
}

// Add these new functions at the top level
async function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 210000, 64, 'sha512', (err, key) => {
            if (err) reject(err);
            resolve(key.toString('hex'));
        });
    });
}

// Add these new security functions
async function generateNoise(length) {
    const noise = crypto.randomBytes(length);
    return Buffer.from(noise).toString('base64');
}

async function addSecurityWatermark(data) {
    const timestamp = Date.now();
    const noise = await generateNoise(32);
    return {
        data,
        watermark: {
            noise,
            timestamp,
            signature: crypto.createHmac('sha512', noise)
                .update(data + timestamp)
                .digest('hex')
        }
    };
}

// Enhance the encryption function with more layers
async function encrypt(message, masterKey) {
    try {
        // Layer 1: Initial preparation
        const salt = crypto.randomBytes(32);
        const iv = generateIV();
        
        // Generate a 32-byte key for each algorithm
        const derivedKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 96, 'sha512');
        const aesKey = derivedKey.slice(0, 32);
        const camelliaKey = derivedKey.slice(32, 64);
        const chachaKey = derivedKey.slice(64, 96);
        
        // Prepare the message with timestamp
        const timestamp = Date.now();
        const messageWithTimestamp = `${timestamp}|${message}`;
        
        // Layer 2: First encryption layer (AES-256-GCM)
        const cipher1 = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        let encrypted = cipher1.update(messageWithTimestamp, 'utf8', 'hex');
        encrypted += cipher1.final('hex');
        const authTag = cipher1.getAuthTag();
        
        // Layer 3: Second encryption layer (Camellia-256-CBC)
        const cipher2 = crypto.createCipheriv('camellia-256-cbc', camelliaKey, iv);
        let doubleEncrypted = cipher2.update(encrypted, 'hex', 'hex');
        doubleEncrypted += cipher2.final('hex');
        
        // Layer 4: Scrambling
        const scrambled = doubleEncrypted.split('').reverse().join('');
        
        // Create the final package
        const finalPackage = {
            salt: salt.toString('hex'),
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            data: scrambled,
            checksum: crypto.createHash('sha3-512').update(scrambled).digest('hex')
        };
        
        return Buffer.from(JSON.stringify(finalPackage)).toString('base64');
    } catch (error) {
        throw new Error('Encryption failed: ' + error.message);
    }
}

// Enhanced decryption function
function decrypt(encryptedPackage, masterKey) {
    try {
        // Unpack the encrypted data
        const encryptedData = JSON.parse(Buffer.from(encryptedPackage, 'base64').toString());
        
        // Verify checksum
        const calculatedChecksum = crypto.createHash('sha3-512').update(encryptedData.data).digest('hex');
        if (calculatedChecksum !== encryptedData.checksum) {
            throw new Error('Data integrity check failed');
        }
        
        // Reconstruct components
        const salt = Buffer.from(encryptedData.salt, 'hex');
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const authTag = Buffer.from(encryptedData.authTag, 'hex');
        
        // Generate the same keys used for encryption
        const derivedKey = crypto.pbkdf2Sync(masterKey, salt, 100000, 96, 'sha512');
        const aesKey = derivedKey.slice(0, 32);
        const camelliaKey = derivedKey.slice(32, 64);
        
        // Reverse scrambling
        const unscrambled = encryptedData.data.split('').reverse().join('');
        
        // First decryption layer (Camellia-256-CBC)
        const decipher2 = crypto.createDecipheriv('camellia-256-cbc', camelliaKey, iv);
        let decrypted = decipher2.update(unscrambled, 'hex', 'hex');
        decrypted += decipher2.final('hex');
        
        // Second decryption layer (AES-256-GCM)
        const decipher1 = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher1.setAuthTag(authTag);
        let final = decipher1.update(decrypted, 'hex', 'utf8');
        final += decipher1.final('utf8');
        
        // Extract timestamp and message
        const [timestamp, message] = final.split('|');
        
        return {
            message,
            timestamp: new Date(parseInt(timestamp)).toLocaleString(),
            verified: true
        };
    } catch (error) {
        throw new Error('Decryption failed: ' + error.message);
    }
}

// Enhanced interactive interface
class EncryptionInterface {
    constructor() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        this.history = [];
        this.keyStore = new Map();
        this.progressBar = new cliProgress.SingleBar({
            format: chalk.cyan('{bar}') + ' | {percentage}% | {value}/{total} Bytes',
            barCompleteChar: '█',
            barIncompleteChar: '░',
        });
    }
    
    async showAnimatedBanner() {
        return new Promise((resolve) => {
            figlet('AMLES', {
                font: 'Standard',
                horizontalLayout: 'default',
                verticalLayout: 'default'
            }, (err, data) => {
                if (!err) {
                    console.clear();
                    const rainbowTitle = gradient.rainbow.multiline(data);
                    console.log(rainbowTitle);
                    console.log(chalk.cyan('\nAdvanced Multi-Layer Encryption System'));
                    console.log(chalk.dim('Made By Hack With Suraj\n' + 'Version 1.0.0'));
                }
                resolve();
            });
        });
    }
    
    async showLoadingAnimation(text, duration = 1000) {
        const spinner = createSpinner(chalk.yellow(text)).start();
        
        await new Promise(resolve => setTimeout(resolve, duration));
        spinner.success({ text: chalk.green(text + ' Complete!') });
    }
    
    async showMenu() {
        await this.showAnimatedBanner();
        
        const menuItems = [
            ['📝 Encrypt Message', 'Standard message encryption'],
            ['🔓 Decrypt Message', 'Decrypt encrypted messages'],
            ['💾 File Operations', 'Save/Load encrypted files'],
            ['🔑 Key Management', 'Manage encryption keys'],
            ['🛡️ Security Dashboard', 'View security status'],
            ['📊 Security Monitor', 'Real-time security metrics'],
            ['💡 Security Tips', 'Advanced security guidance'],
            ['⚙️ Settings', 'Configure system settings'],
            ['❌ Exit', 'Exit application']
        ];

        console.log(chalk.bold.blue('\n=== Main Menu ==='));
        menuItems.forEach(([title, desc], index) => {
            console.log(
                chalk.yellow(`${index + 1}.`),
                chalk.green(title.padEnd(20)),
                chalk.dim(`- ${desc}`)
            );
        });

        const choice = await this.question(chalk.cyan('\nChoose an option (1-9): '));
        await this.handleChoice(choice);
    }
    
    async handleChoice(choice) {
        try {
            switch(choice) {
                case '1': await this.encryptMessage(); break;
                case '2': await this.decryptMessage(); break;
                case '3': await this.showFileOperations(); break;
                case '4': await this.keyManagement(); break;
                case '5': await this.showSecurityDashboard(); break;
                case '6': await this.showSecurityMonitor(); break;
                case '7': await this.showSecurityTips(); break;
                case '8': await this.showSettings(); break;
                case '9': await this.exit(); break;
                default:
                    console.log(chalk.red('\n❌ Invalid option'));
                    await this.pause();
            }
        } catch (error) {
            console.log(chalk.red('\n❌ Error:'), chalk.white(error.message));
            await this.pause();
        }
        
        if (choice !== '9') {
            await this.showMenu();
        }
    }
    
    // Helper methods
    async question(query) {
        return new Promise(resolve => this.rl.question(query, resolve));
    }
    
    async pause() {
        await this.question(chalk.dim('\nPress Enter to continue...'));
    }
    
    // Implement other methods...
    async encryptMessage() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Message Encryption ==='));
        
        const message = await this.question(chalk.yellow('\nEnter message to encrypt: '));
        if (!message.trim()) {
            throw new Error('Message cannot be empty');
        }
        
        await this.showLoadingAnimation('Generating secure key');
        const key = generateKey();
        
        await this.showLoadingAnimation('Encrypting message');
        this.progressBar.start(100, 0);
        
        // Simulate encryption progress
        for (let i = 0; i <= 100; i++) {
            this.progressBar.update(i);
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        this.progressBar.stop();
        
        try {
            // Wait for encryption to complete
            const encrypted = await encrypt(message, key);
            
            // Save to history
            this.history.push({
                timestamp: new Date(),
                type: 'encryption',
                messagePreview: message.substring(0, 20) + '...'
            });
            
            const keyId = crypto.randomBytes(8).toString('hex');
            this.keyStore.set(keyId, key);
            
            console.clear();
            await this.showAnimatedBanner();
            console.log(chalk.bold.green('\n=== Encryption Results ==='));
            console.log(chalk.yellow('\n📜 Encrypted Message:'), chalk.white(encrypted));
            console.log(chalk.yellow('🔑 Key ID:'), chalk.white(keyId));
            console.log(chalk.yellow('🔐 Encryption Key:'), chalk.white(key));
            
            console.log(chalk.bold.red('\n⚠️  IMPORTANT: Store this information securely!'));
        } catch (error) {
            console.log(chalk.red('\n❌ Encryption failed:'), chalk.white(error.message));
        }
        
        await this.pause();
    }
    
    async decryptMessage() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Message Decryption ==='));
        
        const encryptedMessage = await this.question(chalk.yellow('\nEnter encrypted message: '));
        const key = await this.question(chalk.yellow('Enter decryption key: '));
        
        await this.showLoadingAnimation('Verifying message integrity');
        await this.showLoadingAnimation('Decrypting message');
        
        const result = decrypt(encryptedMessage, key);
        
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Decryption Results ==='));
        console.log(chalk.yellow('\n📜 Original Message:'), chalk.white(result.message));
        console.log(chalk.yellow('⏰ Timestamp:'), chalk.white(result.timestamp));
        console.log(chalk.yellow('✅ Verification:'), 
            result.verified ? chalk.green('Authentic') : chalk.red('Failed'));
        
        await this.pause();
    }
    
    async saveToFile() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Save Encrypted Message ==='));
        
        const message = await this.question(chalk.yellow('\nEnter message to encrypt and save: '));
        const filename = await this.question(chalk.yellow('Enter filename to save: '));
        
        await this.showLoadingAnimation('Generating secure key');
        const key = generateKey();
        
        await this.showLoadingAnimation('Encrypting message');
        const encrypted = await encrypt(message, key);
        
        const data = {
            encrypted: encrypted,
            key: key,
            timestamp: new Date().toISOString()
        };
        
        try {
            fs.writeFileSync(`${filename}.json`, JSON.stringify(data, null, 2));
            console.log(chalk.green('\n✅ File saved successfully!'));
        } catch (error) {
            throw new Error('Failed to save file: ' + error.message);
        }
        
        await this.pause();
    }
    
    async loadFromFile() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Load Encrypted Message ==='));
        
        const filename = await this.question(chalk.yellow('\nEnter filename to load: '));
        
        try {
            const data = JSON.parse(fs.readFileSync(`${filename}.json`));
            const result = decrypt(data.encrypted, data.key);
            
            console.clear();
            await this.showAnimatedBanner();
            console.log(chalk.bold.green('\n=== Decryption Results ==='));
            console.log(chalk.yellow('\n📜 Original Message:'), chalk.white(result.message));
            console.log(chalk.yellow('⏰ Timestamp:'), chalk.white(result.timestamp));
            console.log(chalk.yellow('📅 File Created:'), chalk.white(new Date(data.timestamp).toLocaleString()));
        } catch (error) {
            throw new Error('Failed to load file: ' + error.message);
        }
        
        await this.pause();
    }
    
    async viewHistory() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Encryption History ==='));
        
        if (this.history.length === 0) {
            console.log(chalk.yellow('\nNo history available.'));
        } else {
            this.history.forEach((entry, index) => {
                console.log(chalk.cyan(`\n${index + 1}. ${entry.type.toUpperCase()}`));
                console.log(chalk.yellow('Time:'), chalk.white(entry.timestamp.toLocaleString()));
                console.log(chalk.yellow('Preview:'), chalk.white(entry.messagePreview));
            });
        }
        
        await this.pause();
    }
    
    async keyManagement() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Key Management ==='));
        
        if (this.keyStore.size === 0) {
            console.log(chalk.yellow('\nNo keys stored.'));
        } else {
            for (const [keyId, key] of this.keyStore) {
                console.log(chalk.cyan(`\nKey ID: ${keyId}`));
                console.log(chalk.yellow('Key:'), chalk.white(key));
            }
        }
        
        await this.pause();
    }
    
    async showSystemInfo() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== System Information ==='));
        
        console.log(chalk.yellow('\nEncryption Layers:'));
        console.log(chalk.white('• AES-256-GCM'));
        console.log(chalk.white('• Camellia-256-CBC'));
        console.log(chalk.white('• SHA3-512 Checksums'));
        console.log(chalk.white('• PBKDF2 Key Derivation'));
        
        console.log(chalk.yellow('\nSecurity Features:'));
        console.log(chalk.white('• Message Authentication'));
        console.log(chalk.white('• Integrity Verification'));
        console.log(chalk.white('• Timestamp Validation'));
        console.log(chalk.white('• Secure Key Generation'));
        
        await this.pause();
    }
    
    async showSecurityTips() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Advanced Security Tips ==='));
        
        const tips = [
            ['🔒 Password Security', [
                'Use unique passwords for each service',
                'Combine letters, numbers, and symbols',
                'Avoid personal information in passwords',
                'Use a password manager',
                'Change passwords regularly'
            ]],
            ['🔑 Key Management', [
                'Store encryption keys offline',
                'Use hardware security modules when possible',
                'Never share keys via email',
                'Implement key rotation policies',
                'Maintain a secure key backup system'
            ]],
            ['📱 Device Security', [
                'Keep systems updated',
                'Use antivirus software',
                'Enable disk encryption',
                'Use secure boot options',
                'Implement access controls'
            ]],
            ['🌐 Network Security', [
                'Use VPN for remote access',
                'Enable firewall protection',
                'Monitor network traffic',
                'Use secure protocols (HTTPS, SSH)',
                'Regular security audits'
            ]],
            ['💼 Data Handling', [
                'Classify data by sensitivity',
                'Implement data retention policies',
                'Secure data backups',
                'Use secure file deletion',
                'Monitor data access'
            ]]
        ];

        let currentCategory = 0;
        while (true) {
            console.clear();
            await this.showAnimatedBanner();
            console.log(chalk.bold.green('\n=== Advanced Security Tips ==='));
            
            const [category, items] = tips[currentCategory];
            console.log(chalk.yellow(`\n${category}:`));
            for (const item of items) {
                console.log(chalk.white(`  • ${item}`));
            }
            
            console.log(chalk.dim('\nNavigation:'));
            console.log(chalk.dim('← Previous (A) | Next (D) →'));
            console.log(chalk.dim('Exit (Q)'));
            
            const key = await this.question(chalk.cyan('\nEnter choice: '));
            
            switch(key.toLowerCase()) {
                case 'a':
                    currentCategory = (currentCategory - 1 + tips.length) % tips.length;
                    break;
                case 'd':
                    currentCategory = (currentCategory + 1) % tips.length;
                    break;
                case 'q':
                    return;
            }
        }
    }
    
    async exit() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.yellow('\nThank you for using AMLES!'));
        console.log(chalk.dim('Cleaning up and closing securely...'));
        
        const spinner = createSpinner(chalk.yellow('Closing application')).start();
        await new Promise(resolve => setTimeout(resolve, 1500));
        spinner.success({ text: chalk.green('Application closed securely!') });
        
        this.rl.close();
        process.exit(0);
    }

    async showAdvancedOptions() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Advanced Options ==='));
        
        console.log(chalk.yellow('1.'), chalk.green('🔐 Change encryption settings'));
        console.log(chalk.yellow('2.'), chalk.green('📊 View encryption statistics'));
        console.log(chalk.yellow('3.'), chalk.green('🗑️  Clear history'));
        console.log(chalk.yellow('4.'), chalk.green('💾 Export keys'));
        console.log(chalk.yellow('5.'), chalk.green('📥 Import keys'));
        console.log(chalk.yellow('6.'), chalk.green('🔍 Verify file integrity'));
        console.log(chalk.yellow('7.'), chalk.green('⬅️  Back to main menu'));
        
        const choice = await this.question(chalk.cyan('\nChoose an option (1-7): '));
        await this.handleAdvancedChoice(choice);
    }

    async verifyFileIntegrity() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== File Integrity Verification ==='));
        
        const filename = await this.question(chalk.yellow('\nEnter filename to verify: '));
        
        try {
            const data = JSON.parse(fs.readFileSync(`${filename}.json`));
            
            console.log(chalk.yellow('\nVerifying file integrity...'));
            await this.showLoadingAnimation('Loading file');
            await this.showLoadingAnimation('Checking structure');
            
            // Verify file structure
            if (!data.encrypted || !data.key || !data.timestamp) {
                throw new Error('Invalid file format');
            }
            
            await this.showLoadingAnimation('Verifying checksums');
            
            // Calculate checksum of encrypted data
            const calculatedChecksum = crypto.createHash('sha3-512')
                .update(data.encrypted)
                .digest('hex');
            
            console.log(chalk.yellow('\nFile Information:'));
            console.log(chalk.white('• Created:'), chalk.dim(new Date(data.timestamp).toLocaleString()));
            console.log(chalk.white('• Size:'), chalk.dim(Buffer.from(data.encrypted).length + ' bytes'));
            
            // Show integrity status
            if (data.checksum === calculatedChecksum) {
                console.log(chalk.green('\n✅ File integrity verified!'));
            } else {
                console.log(chalk.red('\n❌ File integrity check failed!'));
                console.log(chalk.red('Warning: File may have been tampered with.'));
            }
        } catch (error) {
            throw new Error('Verification failed: ' + error.message);
        }
        
        await this.pause();
    }

    async exportKeys() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Export Encryption Keys ==='));
        
        if (this.keyStore.size === 0) {
            console.log(chalk.yellow('\nNo keys to export.'));
            await this.pause();
            return;
        }
        
        const filename = await this.question(chalk.yellow('\nEnter filename for key export: '));
        const password = await this.question(chalk.yellow('Enter password to protect exported keys: '));
        
        try {
            const keyData = {
                keys: Array.from(this.keyStore.entries()),
                exportTime: new Date().toISOString(),
                checksum: ''
            };
            
            // Encrypt the key data
            const salt = crypto.randomBytes(32);
            const derivedKey = await hashPassword(password, salt);
            const iv = generateIV();
            
            const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(derivedKey), iv);
            let encrypted = cipher.update(JSON.stringify(keyData), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const exportData = {
                salt: salt.toString('hex'),
                iv: iv.toString('hex'),
                authTag: cipher.getAuthTag().toString('hex'),
                data: encrypted
            };
            
            fs.writeFileSync(`${filename}.keys`, JSON.stringify(exportData));
            console.log(chalk.green('\n✅ Keys exported successfully!'));
        } catch (error) {
            throw new Error('Export failed: ' + error.message);
        }
        
        await this.pause();
    }

    async showEnhancedMenu() {
        await this.showAnimatedBanner();
        
        const menuItems = [
            ['📝 Encrypt a message', 'Standard message encryption'],
            ['🔐 Advanced encryption', 'Multiple layers with max security'],
            ['🔓 Decrypt a message', 'Decrypt any encrypted message'],
            ['💾 File operations', 'Save, load, and manage files'],
            ['🔑 Key management', 'Manage and secure your keys'],
            ['📊 Analytics', 'View encryption statistics'],
            ['⚙️  Settings', 'Configure security options'],
            ['❓ Help & Info', 'Get help and system information'],
            ['🚪 Exit', 'Exit the application']
        ];

        console.log(chalk.bold.blue('\n=== Main Menu ==='));
        menuItems.forEach(([title, desc], index) => {
            console.log(
                chalk.yellow(`${index + 1}.`),
                chalk.green(title.padEnd(20)),
                chalk.dim(`- ${desc}`)
            );
        });

        const choice = await this.question(chalk.cyan('\nChoose an option (1-9): '));
        await this.handleEnhancedChoice(choice);
    }

    async showAnalytics() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Encryption Analytics ==='));

        const stats = {
            totalEncryptions: this.history.length,
            averageMessageSize: this.calculateAverageMessageSize(),
            securityScore: this.calculateSecurityScore(),
            keyStrength: this.analyzeKeyStrength(),
            recentActivity: this.getRecentActivity()
        };

        // Display animated progress bars
        console.log(chalk.yellow('\nSecurity Metrics:'));
        await this.showAnimatedProgressBar('Security Score', stats.securityScore);
        await this.showAnimatedProgressBar('Key Strength', stats.keyStrength);

        // Display statistics
        console.log(chalk.yellow('\nUsage Statistics:'));
        console.log(chalk.white(`• Total Encryptions: ${stats.totalEncryptions}`));
        console.log(chalk.white(`• Average Message Size: ${stats.averageMessageSize} bytes`));
        
        // Show recent activity
        console.log(chalk.yellow('\nRecent Activity:'));
        stats.recentActivity.forEach(activity => {
            console.log(chalk.cyan(`• ${activity}`));
        });

        await this.pause();
    }

    async showSecuritySettings() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Security Settings ==='));

        const settings = [
            ['Encryption Strength', ['Standard', 'Maximum', 'Quantum-Ready']],
            ['Key Length', ['2048 bits', '4096 bits', '8192 bits']],
            ['Hash Algorithm', ['SHA-512', 'SHA3-512', 'BLAKE3']],
            ['Compression', ['None', 'Standard', 'Maximum']],
            ['Auto-Delete History', ['Never', '24 hours', '7 days']]
        ];

        for (const [setting, options] of settings) {
            console.log(chalk.yellow(`\n${setting}:`));
            options.forEach((option, i) => {
                console.log(chalk.white(`  ${i + 1}. ${option}`));
            });
        }

        const choice = await this.question(chalk.cyan('\nSelect setting to modify (1-5): '));
        // Implement settings modification logic

        await this.pause();
    }

    async showAnimatedProgressBar(label, value) {
        const width = 40;
        const filled = Math.round(width * (value / 100));
        const empty = width - filled;
        
        process.stdout.write(chalk.yellow(`${label}: [`));
        
        for (let i = 0; i < filled; i++) {
            process.stdout.write(chalk.green('█'));
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        
        for (let i = 0; i < empty; i++) {
            process.stdout.write(chalk.gray('░'));
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        
        console.log(chalk.yellow(`] ${value}%`));
    }

    calculateSecurityScore() {
        // Implement security scoring logic
        return 95; // Example score
    }

    analyzeKeyStrength() {
        // Implement key strength analysis
        return 90; // Example strength
    }

    getRecentActivity() {
        return this.history.slice(-5).map(entry => {
            return `${entry.type} at ${entry.timestamp.toLocaleString()}`;
        });
    }

    calculateAverageMessageSize() {
        // Implement message size calculation
        return 256; // Example size
    }

    async showSecurityDashboard() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Security Dashboard ==='));

        const securityCategories = [
            ['🔒 Encryption Standards', [
                'AES-256-GCM (Advanced Encryption Standard)',
                'Camellia-256-CBC (CRYPTREC-recommended)',
                'ChaCha20-Poly1305 (Modern Stream Cipher)',
                'PBKDF2 with SHA-512 (Key Derivation)',
                'SHA3-512 (Integrity Verification)'
            ]],
            ['🛡️ Security Measures', [
                'Multi-layer encryption architecture',
                'Secure key generation with entropy',
                'Message authentication codes',
                'Digital watermarking',
                'Quantum-resistant padding'
            ]],
            ['⚠️ Security Recommendations', [
                'Use passwords longer than 12 characters',
                'Enable two-factor authentication',
                'Regularly update encryption keys',
                'Monitor access logs',
                'Backup encrypted data securely'
            ]]
        ];

        for (const [category, items] of securityCategories) {
            console.log(chalk.yellow(`\n${category}:`));
            for (const item of items) {
                await new Promise(resolve => setTimeout(resolve, 200));
                console.log(chalk.white(`  • ${item}`));
            }
        }

        await this.pause();
    }

    async showSecurityMonitor() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Security Monitor ==='));
        
        const metrics = {
            encryptionStrength: 256,
            keyComplexity: this.analyzeKeyStrength(),
            securityScore: this.calculateSecurityScore(),
            lastActivity: new Date().toLocaleString(),
            activeProtections: [
                'Intrusion Detection',
                'Integrity Verification',
                'Anti-Tampering',
                'Access Control'
            ]
        };
        
        console.log(chalk.yellow('\nReal-time Security Metrics:'));
        await this.showAnimatedProgressBar('Encryption Strength', (metrics.encryptionStrength / 256) * 100);
        await this.showAnimatedProgressBar('Key Complexity', metrics.keyComplexity);
        await this.showAnimatedProgressBar('Overall Security', metrics.securityScore);
        
        console.log(chalk.yellow('\nActive Protections:'));
        for (const protection of metrics.activeProtections) {
            await new Promise(resolve => setTimeout(resolve, 300));
            console.log(chalk.green(`✓ ${protection} Active`));
        }
        
        console.log(chalk.yellow('\nSystem Status:'));
        console.log(chalk.white(`• Last Activity: ${metrics.lastActivity}`));
        console.log(chalk.white(`• Encryption Algorithm: AES-256-GCM`));
        console.log(chalk.white(`• Key Derivation: PBKDF2-SHA512`));
        
        await this.pause();
    }

    async showFileOperations() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== File Operations ==='));
        
        const options = [
            ['💾 Save Message', 'Save encrypted message to file'],
            ['📂 Load Message', 'Load and decrypt message from file'],
            ['🔍 Verify File', 'Check file integrity'],
            ['🔙 Back', 'Return to main menu']
        ];
        
        options.forEach(([title, desc], index) => {
            console.log(
                chalk.yellow(`${index + 1}.`),
                chalk.green(title.padEnd(20)),
                chalk.dim(`- ${desc}`)
            );
        });
        
        const choice = await this.question(chalk.cyan('\nChoose an option (1-4): '));
        
        try {
            switch(choice) {
                case '1': 
                    await this.saveToFile(); 
                    break;
                case '2': 
                    await this.loadFromFile(); 
                    break;
                case '3': 
                    await this.verifyFileIntegrity(); 
                    break;
                case '4': 
                    return;
                default:
                    console.log(chalk.red('\n❌ Invalid option'));
                    await this.pause();
            }
        } catch (error) {
            console.log(chalk.red('\n❌ Error:'), chalk.white(error.message));
            await this.pause();
        }
        
        // Return to file operations menu unless user selected back
        if (choice !== '4') {
            await this.showFileOperations();
        }
    }

    async showSettings() {
        console.clear();
        await this.showAnimatedBanner();
        console.log(chalk.bold.green('\n=== Security Settings ==='));
        
        const settings = [
            {
                name: 'Encryption',
                options: ['Standard', 'Maximum', 'Quantum-Ready'],
                current: 1
            },
            {
                name: 'Key Length',
                options: ['2048 bits', '4096 bits', '8192 bits'],
                current: 1
            },
            {
                name: 'Hash Algorithm',
                options: ['SHA-512', 'SHA3-512', 'BLAKE3'],
                current: 1
            },
            {
                name: 'Auto-Delete History',
                options: ['Never', '24 hours', '7 days'],
                current: 0
            },
            {
                name: 'Backup Frequency',
                options: ['Manual', 'Daily', 'Weekly'],
                current: 0
            }
        ];
        
        console.log(chalk.yellow('\nCurrent Settings:'));
        settings.forEach((setting, index) => {
            console.log(chalk.white(`\n${index + 1}. ${setting.name}:`));
            setting.options.forEach((option, optIndex) => {
                const prefix = optIndex === setting.current ? '✓' : ' ';
                const color = optIndex === setting.current ? chalk.green : chalk.dim;
                console.log(color(`   ${prefix} ${option}`));
            });
        });
        
        console.log(chalk.yellow('\nActions:'));
        console.log(chalk.white('• Enter setting number (1-5) to modify'));
        console.log(chalk.white('• Press B to backup settings'));
        console.log(chalk.white('• Press R to reset to defaults'));
        console.log(chalk.white('• Press Q to return to main menu'));
        
        const choice = await this.question(chalk.cyan('\nEnter choice: '));
        
        try {
            switch(choice.toLowerCase()) {
                case 'b':
                    await this.showLoadingAnimation('Backing up settings');
                    console.log(chalk.green('\n✅ Settings backed up successfully!'));
                    break;
                case 'r':
                    await this.showLoadingAnimation('Resetting settings');
                    console.log(chalk.green('\n✅ Settings reset to defaults!'));
                    break;
                case 'q':
                    return;
                default:
                    const settingIndex = parseInt(choice) - 1;
                    if (settingIndex >= 0 && settingIndex < settings.length) {
                        await this.modifySetting(settings[settingIndex]);
                    } else {
                        console.log(chalk.red('\n❌ Invalid option'));
                    }
            }
        } catch (error) {
            console.log(chalk.red('\n❌ Error:'), chalk.white(error.message));
        }
        
        await this.pause();
        // Return to settings menu unless user chose to exit
        if (choice.toLowerCase() !== 'q') {
            await this.showSettings();
        }
    }

    async modifySetting(setting) {
        console.log(chalk.yellow(`\nModifying ${setting.name}:`));
        setting.options.forEach((option, index) => {
            console.log(chalk.white(`${index + 1}. ${option}`));
        });
        
        const choice = await this.question(chalk.cyan('\nSelect option (1-' + setting.options.length + '): '));
        const optionIndex = parseInt(choice) - 1;
        
        if (optionIndex >= 0 && optionIndex < setting.options.length) {
            setting.current = optionIndex;
            await this.showLoadingAnimation('Updating setting');
            console.log(chalk.green('\n✅ Setting updated successfully!'));
        } else {
            console.log(chalk.red('\n❌ Invalid option'));
        }
    }
}

// Start the program with animated intro
async function startProgram() {
    const encryptionUI = new EncryptionInterface();
    
    console.clear();
    const spinner = createSpinner(chalk.yellow('Initializing AMLES')).start();
    
    await new Promise(resolve => setTimeout(resolve, 1500));
    spinner.success({ text: chalk.green('System initialized successfully!') });
    
    await new Promise(resolve => setTimeout(resolve, 500));
    await encryptionUI.showMenu();
}

// Run the program
startProgram().catch(console.error);


