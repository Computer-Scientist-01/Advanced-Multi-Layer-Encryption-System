import chalk from 'chalk';
import { FileOperations } from '../utils/fileOperations.js';
import { createSpinner } from 'nanospinner';

export class FileInterface {
    constructor() {
        this.fileOps = new FileOperations();
    }

    // Show loading animation
    async showLoading(text, duration = 1000) {
        const spinner = createSpinner(chalk.yellow(text)).start();
        await new Promise(resolve => setTimeout(resolve, duration));
        return spinner;
    }

    // Main file operations menu
    async showFileMenu() {
        console.clear();
        console.log(chalk.bold.green('\n=== File Operations ===\n'));

        const options = [
            ['📝 Save New File', 'Encrypt and save a new file'],
            ['📖 Load File', 'Load and decrypt a file'],
            ['📋 List Files', 'View all encrypted files'],
            ['🔍 Verify File', 'Check file integrity'],
            ['🗑️  Delete File', 'Delete an encrypted file'],
            ['💾 Backup File', 'Create file backup'],
            ['↩️  Back', 'Return to main menu']
        ];

        options.forEach(([title, desc], index) => {
            console.log(
                chalk.yellow(`${index + 1}.`),
                chalk.green(title.padEnd(20)),
                chalk.dim(`- ${desc}`)
            );
        });

        return options;
    }

    // Handle file saving
    async handleSaveFile(data, filename, key) {
        const spinner = await this.showLoading('Encrypting and saving file');
        try {
            const savedPath = await this.fileOps.saveEncryptedFile(data, filename, key);
            spinner.success({ text: chalk.green('File saved successfully!') });
            return savedPath;
        } catch (error) {
            spinner.error({ text: chalk.red(`Failed to save file: ${error.message}`) });
            throw error;
        }
    }

    // Handle file loading
    async handleLoadFile(filename, key) {
        const spinner = await this.showLoading('Loading and decrypting file');
        try {
            const result = await this.fileOps.loadEncryptedFile(filename, key);
            spinner.success({ text: chalk.green('File loaded successfully!') });
            return result;
        } catch (error) {
            spinner.error({ text: chalk.red(`Failed to load file: ${error.message}`) });
            throw error;
        }
    }

    // Display file list
    async showFileList() {
        const files = this.fileOps.listEncryptedFiles();
        console.log(chalk.yellow('\nEncrypted Files:'));
        
        if (files.length === 0) {
            console.log(chalk.dim('No encrypted files found.'));
            return;
        }

        files.forEach((file, index) => {
            console.log(chalk.white(`\n${index + 1}. ${file.name}`));
            console.log(chalk.dim(`   Created: ${file.created.toLocaleString()}`));
            console.log(chalk.dim(`   Size: ${file.size} bytes`));
        });
    }

    async handleFileSave() {
        console.clear();
        console.log(chalk.bold.green('\n=== Save Encrypted File ===\n'));

        try {
            const data = await this.question(chalk.yellow('Enter the data to encrypt: '));
            const filename = await this.question(chalk.yellow('Enter filename (optional): '));
            const key = await this.question(chalk.yellow('Enter encryption key: '));

            const spinner = await this.showLoading('Processing file');
            
            const result = await this.fileOps.saveEncryptedFile(data, filename, key);
            
            spinner.success({ text: chalk.green('File saved successfully!') });
            
            console.log(chalk.yellow('\nFile Details:'));
            console.log(chalk.white(`Location: ${result.path}`));
            console.log(chalk.white(`Filename: ${result.filename}`));
            console.log(chalk.white(`Size: ${result.metadata.size} bytes`));
            console.log(chalk.white(`Created: ${result.metadata.timestamp}`));
            
            // Show security reminder
            console.log(chalk.red('\n⚠️  Important:'));
            console.log(chalk.dim('- Keep your encryption key safe'));
            console.log(chalk.dim('- Backup your files regularly'));
            console.log(chalk.dim('- Store keys separately from encrypted files'));

        } catch (error) {
            console.error(chalk.red('\n❌ Error:'), error.message);
        }

        await this.pause();
    }

    async question(query) {
        return new Promise(resolve => {
            process.stdout.write(query);
            process.stdin.once('data', data => {
                resolve(data.toString().trim());
            });
        });
    }

    async pause() {
        await this.question(chalk.dim('\nPress Enter to continue...'));
    }
} 