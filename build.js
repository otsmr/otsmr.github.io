// Blindly created out of laziness with ChatGPT. Hopefully it works :)

import fs from 'fs/promises';
import path from 'path';
import { marked } from 'marked';

const pagesDir = './pages/';
const buildDir = './build/';

const initializeBuildDir = async () => {
    try {
        try {
            await fs.access(buildDir);
        } catch (err) {
            if (err.code === 'ENOENT') {
                await fs.mkdir(buildDir);
            } else {
                throw err;
            }
        }
    } catch (err) {
        console.error('Error accessing directory:', err);
    }
};

const convertMarkdownToHtml = async (file) => {
    if (path.extname(file) === '.md') {
        const markdownPath = path.join(pagesDir, file);
        const htmlPath = path.join(buildDir, `${path.basename(file, '.md')}.html`);

        try {
            const data = await fs.readFile(markdownPath, 'utf8');
            let title = "TSMR.eu";
            for (let line of data.split("\n").entries()) {
                if (line[1].startsWith("# ")) {
                    title = line[1].slice(2);
                    break;
                }
            }
            const htmlContent = marked(data);

            let template = await fs.readFile("template.html", 'utf8');
            template = template.replace("{{TITLE}}", title);
            template = template.replace("{{BODY}}", htmlContent);

            await fs.writeFile(htmlPath, template);
            console.log(`Converted ${file} to ${path.basename(file, '.md')}.html`);
        } catch (err) {
            console.error('Error:', err);
        }
    }
};

const convertAllFiles = async () => {
    try {
        await initializeBuildDir();
        const files = await fs.readdir(pagesDir);
        await Promise.all(files.map(convertMarkdownToHtml));
    } catch (err) {
        console.error('Error:', err);
    }
};

const copyFile = async (source, destination) => {
    try {
        const sourceData = await fs.readFile(source);
        await fs.writeFile(destination, sourceData);
        console.log(`Copied ${source} to ${destination}`);
    } catch (err) {
        console.error('Error:', err);
    }
};

const copyDirectory = async (source, destination) => {
    try {
        try {
            await fs.mkdir(destination);
        } catch (error) {

        }
        const files = await fs.readdir(source);
        for (const file of files) {
            const sourcePath = path.join(source, file);
            const destinationPath = path.join(destination, file);
            const fileStat = await fs.stat(sourcePath);
            if (fileStat.isDirectory()) {
                await copyDirectory(sourcePath, destinationPath);
            } else {
                await copyFile(sourcePath, destinationPath);
            }
        }
        console.log(`Copied directory ${source} to ${destination}`);
    } catch (err) {
        console.error('Error:', err);
    }
};

const copyAllFiles = async () => {
    try {
        const files = await fs.readdir(pagesDir);
        await Promise.all(
            files.map(async (file) => {
                const sourcePath = path.join(pagesDir, file);
                const destinationPath = path.join(buildDir, file);
                const fileStat = await fs.stat(sourcePath);
                if (fileStat.isFile() && path.extname(file) !== '.md') {
                    await copyFile(sourcePath, destinationPath);
                } else if (fileStat.isDirectory()) {
                    await copyDirectory(sourcePath, destinationPath);
                }
            })
        );
    } catch (err) {
        console.error('Error:', err);
    }
};

initializeBuildDir();
convertAllFiles();
copyAllFiles();
