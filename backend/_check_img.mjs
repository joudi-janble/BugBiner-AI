import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.resolve(__dirname, '..', 'bugbiner_explained_en.html');
let html = fs.readFileSync(htmlPath, 'utf-8');
const m = html.match(/<img src="data:image\/png;base64,([^"]+)"\/?>/);
if (m) {
  console.log('Base64 found, length: ' + m[1].length);
  console.log('Starts with: ' + m[1].substring(0, 40));
  console.log('Ends with: ' + m[1].substring(m[1].length - 20));
} else {
  console.log('No img tag found!');
  const imgIdx = html.indexOf('<img');
  if (imgIdx >= 0) {
    console.log('Found img at ' + imgIdx);
    console.log('Context: ' + html.substring(imgIdx, imgIdx + 120));
  }
  const b64Idx = html.indexOf('base64');
  if (b64Idx >= 0) {
    console.log('Found base64 at ' + b64Idx);
    console.log('Context: ' + html.substring(b64Idx - 20, b64Idx + 80));
  }
}
