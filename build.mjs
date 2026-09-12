// Builds the itinerary site.
//   node build.mjs            -> index.html + img/*.bin (encrypted with the password in .password)
//   node build.mjs --preview  -> preview.html (unencrypted, for local checks only; never publish)
//
// Encryption: PBKDF2-SHA256 (600k iterations) derives an AES-256-GCM key from the password.
// The page HTML is embedded as ciphertext in index.html; each photo is a separate encrypted file.
// The salt lives in .salt so rebuilding keeps "remembered" devices unlocked; change it (delete .salt)
// together with the password if you ever want to force everyone to re-enter it.
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const ITERATIONS = 600000;
const preview = process.argv.includes("--preview");
const root = new URL("./", import.meta.url);
const path = (p) => new URL(p, root);
const read = (p, enc = "utf8") => readFileSync(path(p), enc);

const trip = JSON.parse(read("src/itinerary.json"));
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// --- images: each source photo gets an opaque name so filenames don't leak anything ---
const images = new Map(); // src -> { out, bytes }
const imgRef = (src) => {
  if (!images.has(src)) images.set(src, { out: `img/${images.size + 1}.bin`, bytes: read(`src/img/${src}`, null) });
  return images.get(src).out;
};
const imgTag = (src, alt, extra = "") =>
  preview
    ? `<img src="src/img/${esc(src)}" alt="${esc(alt)}" ${extra}>`
    : `<img data-enc="${imgRef(src)}" alt="${esc(alt)}" ${extra}>`;

// Reads pixel size from a JPEG's start-of-frame marker so the layout can reserve the right shape.
const jpegSize = (buf) => {
  for (let i = 2; i < buf.length; ) {
    const marker = buf[i + 1], len = buf.readUInt16BE(i + 2);
    if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker))
      return { h: buf.readUInt16BE(i + 5), w: buf.readUInt16BE(i + 7) };
    i += 2 + len;
  }
  throw new Error("Could not read JPEG size");
};
const aspect = (src) => {
  const { w, h } = jpegSize(read(`src/img/${src}`, null));
  return (w / h).toFixed(4);
};

// "{Name|url}" links to url; "{Name}" falls back to a Google Maps search in that day's city.
const linkify = (text, place) =>
  esc(text).replace(/\{([^}|]+)(?:\|([^}]+))?\}/g, (_, name, url) => {
    const href = url ?? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(
      `${name}, ${place === "CDMX" ? "Mexico City" : place}, Mexico`)}`;
    return `<a href="${href}" target="_blank" rel="noopener">${name}</a>`;
  });

// Checkerboard cut-outs echo the deck's title slide. [col,row] cells filled with the page color.
const cuts = (cols, cells) =>
  `<div class="cuts ${cols > 9 ? "wide" : "narrow"}" aria-hidden="true">${Array.from({ length: cols * 3 }, (_, i) =>
    cells.some(([c, r]) => r * cols + c === i) ? "<i></i>" : "<b></b>").join("")}</div>`;

const nav = trip.days
  .map((d) => `<li><a href="#${d.id}"><small>${d.short}</small><span>${d.date.split(".")[1]}</span></a></li>`)
  .join("");

const overview = trip.days
  .map((d) => `<li><a href="#${d.id}"><span>${d.date}</span><span>${esc(d.summary)}</span></a></li>`)
  .join("");

const days = trip.days
  .map((d) => {
    const photos = d.photos || [];
    const items = d.items
      .map(([time, what, opts = {}]) => `
            <li>
              <span class="time">${esc(time)}</span>
              <span class="what">${linkify(what, d.place)}${opts.note ? ` <em>${esc(opts.note)}</em>` : ""}</span>
              ${opts.confirmed ? `<span class="tag">Confirmed</span>` : ""}
            </li>`)
      .join("");
    return `
      <section class="day" id="${d.id}" aria-labelledby="${d.id}-h">
        <div class="day-head">
          <div>
            <h2 id="${d.id}-h">${d.dow} ${d.date}</h2>
            <p class="place">${esc(d.place)}</p>
          </div>
        </div>
        <div class="day-body">
          ${photos.length ? `<div class="photos${photos.length > 1 ? " multi" : ""}">${photos
            .map((p) => `<figure style="--ar:${aspect(p.src)}">${imgTag(p.src, p.alt, 'decoding="async"')}</figure>`).join("")}</div>` : ""}
          <ul class="schedule">${items}</ul>
        </div>
      </section>`;
  })
  .join("");

const content = `
  <header class="hero">
    <div class="hero-inner">
      <h1>${esc(trip.title)}</h1>
      <div class="sub">${trip.subtitle.map((s) => `<span>${esc(s)}</span>`).join("")}</div>
    </div>
  </header>
  <div class="strip">
    ${imgTag(trip.hero.src, trip.hero.alt)}
    ${cuts(9, [[0, 0], [1, 2], [2, 1], [5, 1], [6, 0], [8, 2]])}
    ${cuts(18, [[0, 0], [1, 2], [2, 1], [7, 1], [8, 0], [11, 2], [16, 0], [17, 1]])}
  </div>
  <nav class="daynav" aria-label="Days"><ul>${nav}</ul></nav>
  <main>
    <section class="overview" aria-label="Trip overview">
      <h2>Overview</h2>
      <ul>${overview}</ul>
    </section>
    ${days}
    <footer>
      <span>Tap a place for the map · Times are local</span>
      ${preview ? "" : `<button id="forget" type="button">Lock this device</button>`}
    </footer>
  </main>`;

const template = read("src/template.html");

if (preview) {
  writeFileSync(path("preview.html"), template.replace("<!--PREVIEW-->", content));
  console.log("preview.html written (unencrypted, local only)");
  process.exit(0);
}

const password = existsSync(path(".password")) ? read(".password").split("\n")[0].trim() : "";
if (password.length < 7) throw new Error("Put a password (7+ characters) on the first line of .password");

if (!existsSync(path(".salt"))) writeFileSync(path(".salt"), Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64"));
const salt = Buffer.from(read(".salt").trim(), "base64");

const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const encrypt = async (bytes) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv, data: new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes)) };
};

const page = await encrypt(new TextEncoder().encode(content));
const b64 = (u8) => Buffer.from(u8).toString("base64");
const payload = JSON.stringify({ salt: b64(salt), iv: b64(page.iv), iterations: ITERATIONS, data: b64(page.data) });
writeFileSync(path("index.html"), template.replace("/*PAYLOAD*/null", payload).replace("<!--PREVIEW-->", ""));

rmSync(path("img"), { recursive: true, force: true });
mkdirSync(path("img"));
let total = 0;
for (const { out, bytes } of images.values()) {
  const { iv, data } = await encrypt(bytes);
  writeFileSync(path(out), Buffer.concat([iv, data]));
  total += data.length;
}
console.log(`index.html written; ${images.size} encrypted photos in img/ (${(total / 1024 / 1024).toFixed(1)} MB)`);
