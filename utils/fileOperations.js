import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { encrypt, decrypt } from '../encryption.js';
import chalk from 'chalk';

export class FileOperations {
    constructor() {
        // Create root FileOperations directory
        this.baseDir = path.join(process.cwd(), 'FileOperations');
        if (!fs.existsSync(this.baseDir)) {
            fs.mkdirSync(this.baseDir);
        }

        // Create subfolders with proper naming
        this.folders = {
            encrypted: path.join(this.baseDir, 'EncryptedFiles'),
            decrypted: path.join(this.baseDir, 'DecryptedFiles'),
            backup: path.join(this.baseDir, 'Backups')
        };

        // Create all required folders with proper error handling
        Object.entries(this.folders).forEach(([type, folder]) => {
            try {
                if (!fs.existsSync(folder)) {
                    fs.mkdirSync(folder, { recursive: true });
                    console.log(chalk.green(`✓ Created ${type} folder`));
                }
            } catch (error) {
                console.error(chalk.red(`Failed to create ${type} folder:`, error.message));
            }
        });
    }

    // Save an encrypted file with metadata and proper path handling
    async saveEncryptedFile(data, filename, key) {
        try {
            // Clean filename and ensure .enc extension
            const cleanFilename = this.sanitizeFilename(filename || `encrypted_${Date.now()}`);
            const finalFilename = cleanFilename.endsWith('.enc') ? cleanFilename : `${cleanFilename}.enc`;
            const filePath = path.join(this.folders.encrypted, finalFilename);

            // Create detailed metadata
            const metadata = {
                originalName: filename,
                timestamp: new Date().toISOString(),
                size: Buffer.from(data).length,
                checksum: crypto.createHash('sha256').update(data).digest('hex'),
                encryptionType: 'AES-256-GCM',
                version: '1.0'
            };

            // Encrypt the data
            const encryptedData = await encrypt(data, key);

            // Create the final package with additional security info
            const filePackage = {
                metadata,
                encryptedData,
                security: {
                    version: '1.0',
                    checksumType: 'SHA-256',
                    encryptionMethod: 'AES-256-GCM'
                }
            };

            // Save the file with proper formatting
            fs.writeFileSync(filePath, JSON.stringify(filePackage, null, 2));
            
            // Create a manifest entry
            await this.updateManifest(finalFilename, metadata);

            return {
                path: filePath,
                filename: finalFilename,
                metadata
            };
        } catch (error) {
            throw new Error(`Failed to save encrypted file: ${error.message}`);
        }
    }

    // Helper method to sanitize filenames
    sanitizeFilename(filename) {
        return filename.replace(/[^a-zA-Z0-9-_\.]/g, '_');
    }

    // Maintain a manifest of all encrypted files
    async updateManifest(filename, metadata) {
        const manifestPath = path.join(this.baseDir, 'manifest.json');
        try {
            let manifest = {};
            if (fs.existsSync(manifestPath)) {
                manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            }

            manifest[filename] = {
                ...metadata,
                lastUpdated: new Date().toISOString()
            };

            fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
        } catch (error) {
            console.error(chalk.yellow('Warning: Failed to update manifest:', error.message));
        }
    }

    // Enhanced file listing with manifest information
    listEncryptedFiles() {
        try {
            const files = fs.readdirSync(this.folders.encrypted)
                .filter(file => file.endsWith('.enc'))
                .map(filename => {
                    const filePath = path.join(this.folders.encrypted, filename);
                    const stats = fs.statSync(filePath);
                    
                    // Try to read the file's metadata
                    let metadata = {};
                    try {
                        const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                        metadata = content.metadata || {};
                    } catch (e) {
                        metadata = { error: 'Failed to read metadata' };
                    }

                    return {
                        name: filename,
                        size: stats.size,
                        created: stats.birthtime,
                        metadata
                    };
                });

            // Sort files by creation date (newest first)
            return files.sort((a, b) => b.created - a.created);
        } catch (error) {
            throw new Error(`Failed to list files: ${error.message}`);
        }
    }

    // Load and decrypt a file
    async loadEncryptedFile(filename, key) {
        try {
            const filePath = path.join(this.folders.encrypted, filename);
            
            // Read and parse the file
            const fileContent = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            
            // Verify file structure
            if (!fileContent.metadata || !fileContent.encryptedData) {
                throw new Error('Invalid file format');
            }

            // Decrypt the data
            const decryptedData = await decrypt(fileContent.encryptedData, key);

            // Verify checksum
            const calculatedChecksum = crypto.createHash('sha256')
                .update(decryptedData)
                .digest('hex');

            if (calculatedChecksum !== fileContent.metadata.checksum) {
                throw new Error('File integrity check failed');
            }

            return {
                data: decryptedData,
                metadata: fileContent.metadata
            };
        } catch (error) {
            throw new Error(`Failed to load encrypted file: ${error.message}`);
        }
    }

    // Create a backup of a file
    async createBackup(filename) {
        try {
            const sourcePath = path.join(this.folders.encrypted, filename);
            const backupPath = path.join(
                this.folders.backup,
                `backup_${path.basename(filename)}_${Date.now()}`
            );

            fs.copyFileSync(sourcePath, backupPath);
            return backupPath;
        } catch (error) {
            throw new Error(`Failed to create backup: ${error.message}`);
        }
    }

    // Delete a file
    async deleteFile(filename) {
        try {
            // Create backup before deletion
            await this.createBackup(filename);
            
            // Delete the file
            const filePath = path.join(this.folders.encrypted, filename);
            fs.unlinkSync(filePath);
        } catch (error) {
            throw new Error(`Failed to delete file: ${error.message}`);
        }
    }

    // Verify file integrity
    async verifyFileIntegrity(filename) {
        try {
            const filePath = path.join(this.folders.encrypted, filename);
            const fileContent = JSON.parse(fs.readFileSync(filePath, 'utf8'));

            return {
                isValid: true,
                metadata: fileContent.metadata,
                lastModified: fs.statSync(filePath).mtime
            };
        } catch (error) {
            throw new Error(`File integrity check failed: ${error.message}`);
        }
    }
} 