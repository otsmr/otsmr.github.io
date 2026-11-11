// Static site generator build script

import fs from 'fs/promises';
import path from 'path';
import { marked } from 'marked';

const pagesDir = './pages/';
const buildDir = './build/';
const siteBaseUrl = 'https://tsmr.eu';

const site = {
    name: 'TSMR.eu',
    author: 'Tobi',
    title: 'TSMR.eu – Where usability meets security and privacy',
    description: 'Building twonly, a privacy-friendly alternative to Snapchat, designing usable security '
        + 'protocols like passwordless recovery, and writing about fuzzing, Rust and IT security.',
    keywords: 'IT security, Rust, fuzzing, Flutter, cryptography, protocol design, twonly',
    image: `${siteBaseUrl}/assets/favicon.jpg`,
    sameAs: [
        'https://github.com/otsmr',
        'https://codeberg.org/tsmr',
        'https://infosec.exchange/@tsmreu',
    ],
};

// Pages that should not show up in search results.
const noindexPages = new Set(['imprint.md', 'privacy.md']);
// Pages written in German.
const germanPages = new Set(['imprint.md', 'privacy.md']);

function escapeHtml(unsafe) {
    return String(unsafe).replace(/[<>&'"]/g, (c) => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;', '\'': '&#39;', '"': '&quot;',
    })[c]);
}

function escapeXml(unsafe) {
    return String(unsafe).replace(/[<>&'"]/g, (c) => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;', '\'': '&apos;', '"': '&quot;',
    })[c]);
}

function stripTags(html) {
    return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

// Fills {{PLACEHOLDERS}} in one pass, so content that itself contains
// "{{...}}" or "$&" is inserted verbatim.
function fillTemplate(template, vars) {
    return template.replace(/{{(\w+)}}/g, (match, key) => (key in vars ? vars[key] : match));
}

function jsonLd(data) {
    // Escape "<" so the JSON can never close the script tag.
    const json = JSON.stringify(data, null, 2).replace(/</g, '\\u003c');
    return `    <script type="application/ld+json">\n${json}\n    </script>`;
}

const authorLd = {
    '@type': 'Person',
    name: site.author,
    url: `${siteBaseUrl}/`,
    sameAs: site.sameAs,
};

function renderMarkdown(content) {
    let html = marked(content);

    // Mermaid diagrams
    html = html.replace(/<pre><code class="language-mermaid">([\s\S]*?)<\/code><\/pre>/g, (match, code) => {
        const decoded = code
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'");
        return `<pre class="mermaid">${decoded}</pre>`;
    });

    // Images without alt text inside a <figure> get the caption as alt text.
    html = html.replace(/<figure\b[^>]*>([\s\S]*?)<\/figure>/g, (figure, inner) => {
        const caption = inner.match(/<figcaption\b[^>]*>([\s\S]*?)<\/figcaption>/);
        if (!caption) return figure;
        const alt = escapeHtml(stripTags(caption[1]).replace(/\s*Image source:.*$/i, ''));
        return figure.replace(/<img(?![^>]*\balt=)/g, `<img alt="${alt}"`);
    });

    // Lazy-load images
    html = html.replace(/<img(?![^>]*\bloading=)/g, '<img loading="lazy" decoding="async"');

    // Wide tables scroll horizontally instead of breaking the mobile layout.
    html = html.replace(/<table[\s\S]*?<\/table>/g, (table) => `<div class="table-wrap">${table}</div>`);

    return html;
}

// Reads width/height of a local PNG so the browser can reserve space (no layout shift).
async function pngSize(file) {
    try {
        const handle = await fs.open(file, 'r');
        const buf = Buffer.alloc(24);
        await handle.read(buf, 0, 24, 0);
        await handle.close();
        if (buf.toString('ascii', 12, 16) !== 'IHDR') return null;
        return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
    } catch {
        return null;
    }
}

async function addImageDimensions(html, pageDir, urlPath) {
    const imgs = [...html.matchAll(/<img(?![^>]*\bwidth=)[^>]*\bsrc="([^"]+\.png)"[^>]*>/g)];
    for (const [tag, src] of imgs) {
        if (/^[a-z]+:/i.test(src)) continue;
        const file = src.startsWith('/')
            ? path.join(pagesDir, src)
            : path.join(pageDir, path.relative(urlPath, path.posix.join(urlPath, src)));
        const size = await pngSize(file);
        if (size) {
            html = html.replace(tag, tag.replace('<img', `<img width="${size.width}" height="${size.height}"`));
        }
    }
    return html;
}

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
    let isInsideLinks = false;
    meta.links = [];

    for (let line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        if (trimmed.startsWith('links:')) {
            isInsideLinks = true;
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
                meta[key] = value.replace(/^['"]|['"]$/g, '');
            }
        }
    }

    return { meta, body };
}

function isBlogPostLink(link) {
    const label = link.label.toLowerCase();
    return label === 'blog post' || label === 'blogpost';
}

function linksHtml(links) {
    if (links.length === 0) return '';
    const items = links.map(l => `<li><a href="${escapeHtml(l.url)}">${escapeHtml(l.label)}</a></li>`).join('');
    return `<ul class="links">${items}</ul>`;
}

function formatKeywords(keywords) {
    return keywords.split(',').map(k => k.trim()).filter(Boolean).join(', ');
}

function keywordsHtml(keywords) {
    return formatKeywords(keywords).split(', ').filter(Boolean)
        .map(k => `<span class="keyword">${escapeHtml(k)}</span>`).join(', ');
}

function generateBlogListHtml(posts) {
    const sorted = [...posts].sort((a, b) => b.date.localeCompare(a.date));

    // Each entry is a single HTML block without blank lines, so marked leaves it untouched.
    return sorted.map((post) => {
        const links = [
            { label: 'Blog post', url: post.url },
            ...post.links.filter(l => !isBlogPostLink(l)),
        ];
        return [
            '<article class="post-card">',
            `<h2><a href="${post.url}">${escapeHtml(post.title)}</a></h2>`,
            `<p class="metadata"><time datetime="${post.date}">${post.date}</time> • ${keywordsHtml(post.keywords)}</p>`,
            `<p>${escapeHtml(post.description)}</p>`,
            linksHtml(links),
            '</article>',
        ].join('\n');
    }).join('\n\n');
}

function readingTime(markdown) {
    const words = markdown
        .replace(/```[\s\S]*?```/g, ' ')
        .replace(/<[^>]*>/g, ' ')
        .split(/\s+/)
        .filter(Boolean).length;
    return Math.max(1, Math.round(words / 230));
}

function assetsFor(html) {
    const styles = [];
    const scripts = [];
    if (html.includes('<pre><code')) {
        styles.push('<link rel="stylesheet" href="/assets/atom-one-dark.min.css">');
        scripts.push('<script defer src="/assets/highlight.min.js"></script>');
        scripts.push('<script>addEventListener("DOMContentLoaded", () => hljs.highlightAll());</script>');
    }
    if (/class="(fa-|fa |fas|fab|far)/.test(html)) {
        // Icons are only used inside the content, so they must not block the first render.
        styles.push('<link rel="stylesheet" href="/assets/css/all.min.css" media="print" onload="this.media=\'all\'">');
        styles.push('<noscript><link rel="stylesheet" href="/assets/css/all.min.css"></noscript>');
    }
    if (html.includes('class="mermaid"')) {
        scripts.push(`<script type="module">
        const script = document.createElement('script');
        script.src = '/assets/mermaid.min.js';
        script.onload = () => {
            mermaid.initialize({
                startOnLoad: false,
                theme: 'dark',
                sequence: { useMaxWidth: false, actorFontSize: 10, noteFontSize: 10, messageFontSize: 10 },
            });
            mermaid.run();
        };
        document.body.appendChild(script);
    </script>`);
    }
    const indent = (list) => list.map(s => `    ${s}`).join('\n');
    return { STYLES: indent(styles), SCRIPTS: indent(scripts) };
}

let templateCache = null;
const loadTemplate = async () => {
    templateCache ??= await fs.readFile('template.html', 'utf8');
    return templateCache;
};

const renderPage = async (vars) => {
    const template = await loadTemplate();
    return fillTemplate(template, {
        LANG: 'en',
        OG_LOCALE: 'en_US',
        AUTHOR: escapeHtml(site.author),
        ROBOTS: 'index, follow, max-image-preview:large',
        IMAGE: site.image,
        TWITTER_CARD: 'summary',
        OG_TYPE: 'website',
        HEAD_EXTRA: '',
        HEADER_TAG: 'div',
        ...assetsFor(vars.BODY),
        ...vars,
    });
};

const convertBlogPost = async (slug) => {
    const postDir = path.join(pagesDir, 'blog', slug);
    const mdPath = path.join(postDir, 'index.md');
    const destDir = path.join(buildDir, 'blog', slug);

    await fs.mkdir(destDir, { recursive: true });

    const data = await fs.readFile(mdPath, 'utf8');
    const { meta, body } = parseFrontMatter(data);

    const title = meta.title || site.name;
    const date = meta.date || '';
    const description = meta.description || '';
    const keywords = meta.keywords || '';
    const url = `/blog/${slug}/`;
    const canonical = `${siteBaseUrl}${url}`;
    const links = (meta.links || []).filter(l => !isBlogPostLink(l));

    let htmlContent = await addImageDimensions(renderMarkdown(body), postDir, url);

    // Date, reading time and project links directly below the post title.
    const metaHtml = `<div class="post-meta">`
        + `<p class="metadata"><time datetime="${date}">${date}</time> • ${readingTime(body)} min read`
        + (keywords ? ` • ${keywordsHtml(keywords)}` : '') + `</p>`
        + linksHtml(links)
        + `</div>`;
    if (/<\/h1>/.test(htmlContent)) {
        htmlContent = htmlContent.replace(/<\/h1>/, `</h1>\n${metaHtml}`);
    } else {
        htmlContent = `<h1>${escapeHtml(title)}</h1>\n${metaHtml}\n${htmlContent}`;
    }

    // First image of the post is used as preview image when sharing.
    const firstImage = htmlContent.match(/<img[^>]*\bsrc="([^"]+)"/);
    const image = firstImage ? new URL(firstImage[1], canonical).href : site.image;

    const tags = formatKeywords(keywords).split(', ').filter(Boolean);
    const headExtra = [
        keywords ? `    <meta name="keywords" content="${escapeHtml(keywords)}">` : '',
        date ? `    <meta property="article:published_time" content="${date}">` : '',
        `    <meta property="article:author" content="${siteBaseUrl}/">`,
        ...tags.map(t => `    <meta property="article:tag" content="${escapeHtml(t)}">`),
        jsonLd({
            '@context': 'https://schema.org',
            '@type': 'BlogPosting',
            headline: title,
            description,
            url: canonical,
            mainEntityOfPage: canonical,
            datePublished: date,
            dateModified: date,
            inLanguage: 'en',
            keywords: tags,
            image,
            author: authorLd,
            publisher: authorLd,
        }),
    ].filter(Boolean).join('\n');

    const page = await renderPage({
        TITLE: escapeHtml(`${title} – ${site.name}`),
        OG_TITLE: escapeHtml(title),
        DESCRIPTION: escapeHtml(description),
        CANONICAL: canonical,
        OG_TYPE: 'article',
        IMAGE: escapeHtml(image),
        TWITTER_CARD: firstImage ? 'summary_large_image' : 'summary',
        HEAD_EXTRA: headExtra,
        BODY: `<article class="blog-post">\n${htmlContent}\n<p class="back"><a href="/">← All posts</a></p>\n</article>`,
    });

    await fs.writeFile(path.join(destDir, 'index.html'), page);
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
    const sorted = [...posts].sort((a, b) => b.date.localeCompare(a.date));

    let rss = `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title>TSMR.eu</title>
    <link>${siteBaseUrl}/</link>
    <description>${escapeXml(site.description)}</description>
    <language>en-us</language>
    <atom:link href="${siteBaseUrl}/rss.xml" rel="self" type="application/rss+xml" />
`;
    if (sorted.length > 0) {
        rss += `    <lastBuildDate>${new Date(sorted[0].date).toUTCString()}</lastBuildDate>\n`;
    }

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

const generateSitemap = async (posts) => {
    const sorted = [...posts].sort((a, b) => b.date.localeCompare(a.date));
    const entries = [
        { loc: `${siteBaseUrl}/`, lastmod: sorted[0]?.date },
        ...sorted.map(p => ({ loc: `${siteBaseUrl}${p.url}`, lastmod: p.date })),
    ];
    const urls = entries.map(e => `  <url>\n    <loc>${e.loc}</loc>\n`
        + (e.lastmod ? `    <lastmod>${e.lastmod}</lastmod>\n` : '')
        + `  </url>`).join('\n');
    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`;
    await fs.writeFile(path.join(buildDir, 'sitemap.xml'), sitemap, 'utf8');
    await fs.writeFile(path.join(buildDir, 'robots.txt'),
        `User-agent: *\nAllow: /\n\nSitemap: ${siteBaseUrl}/sitemap.xml\n`, 'utf8');
    console.log('Generated sitemap.xml and robots.txt');
};

const convertMarkdownToHtml = async (file, blogPosts = []) => {
    if (path.extname(file) !== '.md') return;

    const name = path.basename(file, '.md');
    const markdownPath = path.join(pagesDir, file);
    const htmlPath = path.join(buildDir, `${name}.html`);
    const isIndex = file === 'index.md';

    try {
        let data = await fs.readFile(markdownPath, 'utf8');

        // If it is index.md, inject the dynamic blog posts list
        if (isIndex) {
            data = data.replace('{{BLOG_POSTS}}', generateBlogListHtml(blogPosts));
        }

        let heading = null;
        for (const line of data.split('\n')) {
            if (line.startsWith('# ')) {
                heading = line.slice(2).trim();
                break;
            }
        }

        const canonical = isIndex ? `${siteBaseUrl}/` : `${siteBaseUrl}/${name}.html`;
        const isGerman = germanPages.has(file);
        const title = isIndex ? site.title : `${heading || name} – ${site.name}`;
        const description = isIndex
            ? site.description
            : `${heading || name} – ${site.name}`;

        const headExtra = isIndex ? [
            `    <meta name="keywords" content="${escapeHtml(site.keywords)}">`,
            jsonLd({
                '@context': 'https://schema.org',
                '@graph': [
                    {
                        '@type': 'WebSite',
                        name: site.name,
                        url: `${siteBaseUrl}/`,
                        description: site.description,
                        inLanguage: 'en',
                        author: authorLd,
                    },
                    {
                        '@type': 'Blog',
                        name: site.name,
                        url: `${siteBaseUrl}/`,
                        author: authorLd,
                        blogPost: [...blogPosts]
                            .sort((a, b) => b.date.localeCompare(a.date))
                            .map(p => ({
                                '@type': 'BlogPosting',
                                headline: p.title,
                                url: `${siteBaseUrl}${p.url}`,
                                datePublished: p.date,
                            })),
                    },
                ],
            }),
        ].join('\n') : '';

        const page = await renderPage({
            LANG: isGerman ? 'de' : 'en',
            OG_LOCALE: isGerman ? 'de_DE' : 'en_US',
            TITLE: escapeHtml(title),
            OG_TITLE: escapeHtml(isIndex ? site.title : (heading || name)),
            DESCRIPTION: escapeHtml(description),
            CANONICAL: canonical,
            ...(noindexPages.has(file) ? { ROBOTS: 'noindex, follow' } : {}),
            HEADER_TAG: isIndex ? 'h1' : 'div',
            HEAD_EXTRA: headExtra,
            BODY: renderMarkdown(data),
        });

        await fs.writeFile(htmlPath, page);
        console.log(`Converted ${file} to ${name}.html`);
    } catch (err) {
        console.error('Error:', err);
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
                const postDir = path.join(pagesDir, 'blog', subdir);
                const stat = await fs.stat(postDir);
                if (!stat.isDirectory()) continue;
                // Skip drafts that do not have an index.md yet
                const hasIndex = await fs.access(path.join(postDir, 'index.md')).then(() => true, () => false);
                if (!hasIndex) {
                    console.log(`Skipping ${subdir}: no index.md`);
                    continue;
                }
                blogPosts.push(await convertBlogPost(subdir));
            }
        } catch (err) {
            console.error('Error reading blog posts directory:', err);
        }

        // 2. Generate RSS feed, sitemap and robots.txt
        await generateRssFeed(blogPosts);
        await generateSitemap(blogPosts);

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
            if (file === '.DS_Store') continue;
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
                if (file === 'blog' || file === '.DS_Store') return;
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
