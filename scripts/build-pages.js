// Builds the phone / GitHub Pages version into docs/ from public/.
// Run after changing public/index.html:   node scripts/build-pages.js
// GitHub Pages serves docs/ at https://<user>.github.io/<repo>/, so every
// path is made relative and the server calls are handled by local-api.js.
const fs   = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pub  = path.join(root, 'public');
const out  = path.join(root, 'docs');

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(path.join(out, 'icons'), { recursive: true });

// index.html — relative paths + load local-api.js before anything else
let html = fs.readFileSync(path.join(pub, 'index.html'), 'utf8');
html = html
  .replace(/(href|src)="\/(manifest\.webmanifest|icons\/)/g, '$1="$2')
  .replace("register('/sw.js')", "register('sw.js')")
  .replace('<meta charset="UTF-8" />', '<meta charset="UTF-8" />\n  <script src="local-api.js"></script>');
if (!html.includes('local-api.js') || html.includes('"/icons/') || html.includes("'/sw.js'")) {
  throw new Error('build-pages: index.html changed shape — update the replacements above');
}
fs.writeFileSync(path.join(out, 'index.html'), html);

fs.copyFileSync(path.join(root, 'pages', 'local-api.js'), path.join(out, 'local-api.js'));
for (const f of fs.readdirSync(path.join(pub, 'icons'))) {
  fs.copyFileSync(path.join(pub, 'icons', f), path.join(out, 'icons', f));
}

// manifest — relative start_url/scope/icons
const manifest = JSON.parse(fs.readFileSync(path.join(pub, 'manifest.webmanifest'), 'utf8'));
manifest.start_url = './';
manifest.scope     = './';
manifest.icons     = manifest.icons.map(i => ({ ...i, src: i.src.replace(/^\//, '') }));
fs.writeFileSync(path.join(out, 'manifest.webmanifest'), JSON.stringify(manifest, null, 2) + '\n');

// service worker — relative shell paths
let sw = fs.readFileSync(path.join(pub, 'sw.js'), 'utf8');
sw = sw
  .replace("const SHELL = ['/', '/index.html', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];",
           "const SHELL = ['./', 'index.html', 'local-api.js', 'manifest.webmanifest', 'icons/icon-192.png', 'icons/icon-512.png'];")
  .replace("caches.match('/index.html')", "caches.match('index.html')")
  .replace("const CACHE = 'content-ai-v2';", "const CACHE = 'content-ai-pages-v2';");
if (!sw.includes("'local-api.js'")) throw new Error('build-pages: sw.js changed shape — update the replacements above');
fs.writeFileSync(path.join(out, 'sw.js'), sw);

// GitHub Pages: serve files as-is (no Jekyll processing)
fs.writeFileSync(path.join(out, '.nojekyll'), '');

console.log('Built docs/ for GitHub Pages');
