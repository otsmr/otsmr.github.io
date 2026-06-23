// Static site generator build script

import fs from 'fs/promises';
import path from 'path';
import { marked } from 'marked';

function renderMarkdown(content) {
    let htmlContent = marked(content);
    htmlContent = htmlContent.replace(/<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g, (match, code) => {
        const decoded = code
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'");
        return `<pre class="mermaid">${decoded}</pre>`;
    });
    return htmlContent;
}

const pagesDir = './pages/';
const buildDir = './build/';
const siteBaseUrl = 'https://tsmr.eu';

const initializeBuildDir = async () => {
    try {
        await fs.rm(buildDir, { recursive: true, force: true });
        await fs.mkdir(buildDir, { recursive: true });
    } catch (err) {
        console.error('Error initializing build directory:', err);
    }
};

function parseFrontMatter(content) {
    const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
    if (!match) {
        return { meta: {}, body: content };
    }
    const yamlBlock = match[1];
    const body = match[2];
    const meta = {};

    const lines = yamlBlock.split('\n');
    let currentKey = null;
    let isInsideLinks = false;
    meta.links = [];

    for (let line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        if (trimmed.startsWith('links:')) {
            isInsideLinks = true;
            currentKey = 'links';
        } else if (isInsideLinks && trimmed.startsWith('-')) {
            const linkVal = trimmed.replace(/^-\s*/, '').trim();
            const parts = linkVal.split('|').map(p => p.trim());
            if (parts.length >= 2) {
                meta.links.push({ label: parts[0], url: parts.slice(1).join('|') });
            }
        } else {
            isInsideLinks = false;
            const colonIndex = line.indexOf(':');
            if (colonIndex !== -1) {
                const key = line.slice(0, colonIndex).trim();
                const value = line.slice(colonIndex + 1).trim();
                currentKey = key;
                meta[key] = value.replace(/^['"]|['"]$/g, '');
            }
        }
    }

    return { meta, body };
}

function generateBlogListHtml(posts) {
    // Sort posts by date descending
    const sorted = [...posts].sort((a, b) => b.date.localeCompare(a.date));

    let markdown = '';
    for (const post of sorted) {
        markdown += `## ${post.title}\n`;
        markdown += `<span class="metadata">${post.date} • ${post.keywords}</span>\n\n`;
        markdown += `${post.description}\n\n`;
        markdown += `<ul class="links">\n`;
        markdown += `  <li><a href="blog/${post.slug}/">Blog post</a></li>\n`;
        for (const link of post.links) {
            markdown += `  <li><a href="${link.url}">${link.label}</a></li>\n`;
        }
        markdown += `</ul>\n\n`;
        markdown += `<br />\n\n`;
    }
    return markdown;
}

const convertBlogPost = async (slug) => {
    const postDir = path.join(pagesDir, 'blog', slug);
    const mdPath = path.join(postDir, 'index.md');
    const destDir = path.join(buildDir, 'blog', slug);

    await fs.mkdir(destDir, { recursive: true });

    const data = await fs.readFile(mdPath, 'utf8');
    const { meta, body } = parseFrontMatter(data);

    const title = meta.title || "TSMR.eu";
    const date = meta.date || "";
    const description = meta.description || "";
    const keywords = meta.keywords || "";
    const url = `/blog/${slug}/`;

    const htmlContent = renderMarkdown(body);

    // Filter out any "Blog post" links
    const filteredLinks = (meta.links || []).filter(link =>
        link.label.toLowerCase() !== 'blog post' &&
        link.label.toLowerCase() !== 'blogpost'
    );

    let linksHtml = '';
    if (filteredLinks.length > 0) {
        linksHtml += '<br /><br /><ul class="links">\n';
        for (const link of filteredLinks) {
            linksHtml += `  <li><a href="${link.url}">${link.label}</a></li>\n`;
        }
        linksHtml += '</ul>\n';
    }

    let template = await fs.readFile("template-blog.html", 'utf8');
    template = template.replace(/{{TITLE}}/g, title);
    template = template.replace(/{{DESCRIPTION}}/g, description);
    template = template.replace(/{{KEYWORDS}}/g, keywords);
    template = template.replace(/{{URL}}/g, url);
    template = template.replace(/{{DATE}}/g, date);
    template = template.replace(/{{BODY}}/g, htmlContent);
    template = template.replace(/{{LINKS}}/g, linksHtml);

    await fs.writeFile(path.join(destDir, 'index.html'), template);
    console.log(`Converted blog post ${slug}`);

    // Copy blog-specific assets if they exist
    const sourceAssets = path.join(postDir, 'assets');
    const destAssets = path.join(destDir, 'assets');
    try {
        await fs.access(sourceAssets);
        await copyDirectory(sourceAssets, destAssets);
    } catch (err) {
        // assets dir does not exist or error reading it
    }

    return {
        slug,
        title,
        date,
        description,
        keywords,
        links: meta.links || [],
        url
    };
};

const generateRssFeed = async (posts) => {
    // Sort posts by date descending
    const sorted = [...posts].sort((a, b) => b.date.localeCompare(a.date));

    let rss = `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title>TSMR.eu</title>
    <link>${siteBaseUrl}</link>
    <description>Something with IT security and Rust</description>
    <language>en-us</language>
    <atom:link href="${siteBaseUrl}/rss.xml" rel="self" type="application/rss+xml" />
`;

    for (const post of sorted) {
        const pubDate = new Date(post.date).toUTCString();
        const postUrl = `${siteBaseUrl}${post.url}`;

        rss += `    <item>
        <title>${escapeXml(post.title)}</title>
        <link>${postUrl}</link>
        <guid isPermaLink="true">${postUrl}</guid>
        <pubDate>${pubDate}</pubDate>
        <description>${escapeXml(post.description)}</description>
    </item>\n`;
    }

    rss += `</channel>
</rss>`;

    const destPath = path.join(buildDir, 'rss.xml');
    await fs.writeFile(destPath, rss, 'utf8');
    console.log(`Generated RSS feed at ${destPath}`);
};

function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

const convertMarkdownToHtml = async (file, blogPosts = []) => {
    if (path.extname(file) === '.md') {
        const markdownPath = path.join(pagesDir, file);
        const htmlPath = path.join(buildDir, `${path.basename(file, '.md')}.html`);

        try {
            let data = await fs.readFile(markdownPath, 'utf8');

            // If it is index.md, inject the dynamic blog posts list
            if (file === 'index.md') {
                const blogListHtml = generateBlogListHtml(blogPosts);
                data = data.replace('{{BLOG_POSTS}}', blogListHtml);
            }

            let title = "TSMR.eu";
            for (let line of data.split("\n").entries()) {
                if (line[1].startsWith("# ")) {
                    title = line[1].slice(2);
                    break;
                }
            }
            const htmlContent = renderMarkdown(data);

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

        // 1. Scan and convert blog posts
        let blogPosts = [];
        try {
            const blogSubdirs = await fs.readdir(path.join(pagesDir, 'blog'));
            for (const subdir of blogSubdirs) {
                const stat = await fs.stat(path.join(pagesDir, 'blog', subdir));
                if (stat.isDirectory()) {
                    const post = await convertBlogPost(subdir);
                    blogPosts.push(post);
                }
            }
        } catch (err) {
            console.error('Error reading blog posts directory:', err);
        }

        // 2. Generate RSS Feed
        await generateRssFeed(blogPosts);

        // 3. Convert normal markdown files
        const files = await fs.readdir(pagesDir);
        await Promise.all(
            files.map(async (file) => {
                const sourcePath = path.join(pagesDir, file);
                const fileStat = await fs.stat(sourcePath);
                if (fileStat.isFile() && path.extname(file) === '.md') {
                    await convertMarkdownToHtml(file, blogPosts);
                }
            })
        );
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
            await fs.mkdir(destination, { recursive: true });
        } catch (error) {
            // Already exists or other harmless error
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
                if (file === 'blog') return; // Skip pages/blog dir
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

const main = async () => {
    await initializeBuildDir();
    await convertAllFiles();
    await copyAllFiles();
};

main();
