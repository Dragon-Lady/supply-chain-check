"use strict";
// Offline, bounded inspection. Never import or execute inspected files.
const fs = require("fs");
const path = require("path");
const {incidentalJson} = require("./metadata-scope");
const SOURCES = {
  worm: "https://safedep.io/testmetest-npm-worm-miasma-variant/",
  litellm: "https://docs.litellm.ai/blog/security-incident-oct-21-2026",
  dropper: "https://safedep.io/hugo-paper-mevn-cli-forged-commit-preinstall-dropper/",
  brotli: "https://github.com/advisories/GHSA-9v8h-qqgm-4m35",
  pillow: "https://github.com/python-pillow/Pillow/security/advisories/GHSA-w889-685w-c8fh"
};
// Only versions explicitly classified malicious in the dated research table.
const BAD_NPM = {
  "event-bus-lite-testmetest": ["0.0.1"],
  "data-pipeline-testmetest": ["2.0.1"],
  "event-emitter-testmetest": ["1.0.7", "4.1.0", "5.0.0"],
  "test-brotli-testmetest": ["1.0.0"],
  "pixel-map-testmetest": ["0.0.1", "0.0.2"],
  "net-codec-testmetest": ["1.0.1"],
  "log-rotate-testmetest": ["1.0.1"]
};
const NPM_FILES = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]);
const PYTHON_FILES = new Set(["requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock", "METADATA", "PKG-INFO"]);
const CONTAINER_FILES = new Set(["Dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"]);
const STARTUP_FILES = new Set(["cook.pth", "cook.py", "sitecustomize.py"]);
const SERVICE_FILES = new Set(["net-health-checker.service", "pkg-runtime.service", "net-health-checker.sh", "com.user.net-health-checker.plist", "com.user.pkg-runtime.plist"]);
const ORDER = "If execution is possible, preserve evidence and have incident response assess and safely stop the token-revocation wiper before revoking or rotating credentials from any device. A match does not prove execution or an armed wiper. This scanner makes no changes.";
const LITELLM_ORDER = "Do not start Python or pip in a suspected affected environment: startup hooks can run before imports. Preserve evidence and contain/rebuild the environment; rotate exposed credentials from a clean device after containment. A metadata match does not establish execution.";
// The vendor gives only prefixes for these variants. They require review, not an exact-hash verdict.
const DIGEST_PREFIXES = {"ghcr.io/berriai/litellm-database":"c00f9d92c427", "ghcr.io/berriai/litellm-non_root":"7b00e91cd2fe"};
const DIGEST = "1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e";
const within = (root, file) => { const relative = path.relative(path.resolve(root), path.resolve(file)); return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative)); };
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function candidate(file) {
  const base = path.basename(file);
  return NPM_FILES.has(base) || PYTHON_FILES.has(base) || CONTAINER_FILES.has(base) || STARTUP_FILES.has(base) || SERVICE_FILES.has(base) || base === "binding.gyp" || base === "preinstall.js";
}
function finding(file, severity, type, message, source) {
  return {severity, type, path:file, message, evidence:{source, lastVerified:"2026-10-23", activation:"not-assessed"}};
}
function incomplete(file) {
  return finding(file, "medium", "october23-coverage-incomplete", "October 23 candidate inspection was incomplete (unreadable, malformed, linked, changed, or over budget). Content and error details are withheld.", SOURCES.worm);
}
function read(file, root) {
  if (fs.lstatSync(file).isSymbolicLink()) throw Error("linked candidate");
  if (root && (!within(root, file) || (path.resolve(root) !== path.resolve(file) && !within(fs.realpathSync(root), fs.realpathSync(path.dirname(file)))))) throw Error("outside scope");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = fs.fstatSync(fd);
    const limit = NPM_FILES.has(path.basename(file)) ? 32 * 1024 * 1024 : 2 * 1024 * 1024;
    if (!before.isFile() || before.size > limit) throw Error("budget");
    const buffer = Buffer.alloc(before.size); let offset = 0;
    while (offset < buffer.length) { const n = fs.readSync(fd, buffer, offset, buffer.length-offset, offset); if (!n) throw Error("changed"); offset += n; }
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw Error("changed");
    return buffer.toString("utf8");
  } finally { fs.closeSync(fd); }
}
function npmMatches(text, base) {
  const matches = new Set();
  const add = (name, version) => { if (Object.hasOwn(BAD_NPM, name) && BAD_NPM[name].includes(version)) matches.add(`${name}@${version}`); };
  const alias = value => { if (typeof value !== "string") return; const m = value.match(/^npm:([^@]+)@([^\s]+)$/); if (m) add(m[1], m[2]); };
  if (base.endsWith(".json")) {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) throw Error("metadata");
    add(data.name, data.version);
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, value] of Object.entries(data[section] || {})) { add(name,value); alias(value); }
    }
    for (const [key, value] of Object.entries(data.packages || {})) {
      const name = value?.name || key.match(/(?:^|\/)node_modules\/([^/]+)$/)?.[1];
      add(name, value?.version); alias(value?.version);
    }
    const pending = [data.dependencies]; let count = 0;
    while (pending.length && count++ < 100000) {
      const deps = pending.pop(); if (!deps || typeof deps !== "object") continue;
      for (const [name,value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        add(name,value.version); alias(value.version); if (value.dependencies) pending.push(value.dependencies);
      }
    }
    if (pending.length) throw Error("budget");
  } else {
    for (const [name, versions] of Object.entries(BAD_NPM)) for (const version of versions) {
      const n=escape(name), v=escape(version);
      if (base === "pnpm-lock.yaml" && new RegExp(`^\\s*['"]?\\/?${n}(?:@|/)${v}(?:\\([^\\r\\n]*\\))?['"]?:\\s*(?:\\{\\})?\\s*$`, "m").test(text)) add(name,version);
      if (base === "yarn.lock") for (const block of text.split(/(?=^\S)/m)) {
        const key = block.split(/\r?\n/,1)[0];
        if (new RegExp(`(?:^|,\\s*)["']?(?:${n}@|[^@,\\s"']+@npm:${n}@)`).test(key) && new RegExp(`^\\s+version\\s*:?[ \\t]+["']?${v}["']?\\s*$`,"m").test(block)) add(name,version);
      }
    }
  }
  return [...matches];
}
// Split TOML statements/items only outside strings, arrays and inline tables.
// This reads supported dependency fields; it never evaluates TOML or imports code.
function tomlParts(text, separator) {
  const parts=[], brackets=[]; let value="", quote="", escaped=false;
  const finish=()=>{ if(value.trim()) parts.push(value.trim()); value=""; if(parts.length>100000) throw Error("metadata budget"); };
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(quote) {
      if(escaped) {value+=c;escaped=false;continue;}
      if(quote[0]==='"' && c==='\\') {value+=c;escaped=true;continue;}
      if(text.startsWith(quote,i)) {value+=quote;i+=quote.length-1;quote="";continue;}
      value+=c;continue;
    }
    if(c==='#') {while(i<text.length && text[i]!=='\n')i++; if(i===text.length)break;}
    const next=text[i];
    if(next==='"' || next==="'") {
      quote=text.startsWith(next.repeat(3),i)?next.repeat(3):next;
      value+=quote;i+=quote.length-1;continue;
    }
    if(next==='[' || next==='{')brackets.push(next);
    else if(next===']' || next==='}') {if(brackets.pop()!==(next===']'?'[':'{'))throw Error("malformed metadata");}
    if(next===separator && brackets.length===0)finish();else value+=next;
  }
  if(quote || brackets.length)throw Error("incomplete metadata");
  finish();return parts;
}
function tomlString(value) {
  if(/^"(?:[^"\\]|\\.)*"$/.test(value) && !value.startsWith('"""'))return JSON.parse(value);
  if(/^'[^']*'$/.test(value))return value.slice(1,-1);
  throw Error("unsupported dependency string");
}
function tomlPair(statement) {
  const m=statement.match(/^([A-Za-z0-9_-]+|"[^"\r\n]+"|'[^'\r\n]+')\s*=\s*([\s\S]+)$/);
  if(!m)return null;
  return [m[1].startsWith('"')||m[1].startsWith("'")?tomlString(m[1]):m[1],m[2].trim()];
}
function pythonPackages(text, base) {
  const packages=[];
  const add=(name,version,poetryArray=false)=>{
    name=String(name).toLowerCase().replace(/[-_.]+/g,"-");
    if(["litellm","brotli","brotlicffi","pillow"].includes(name))packages.push({name,version,poetryArray});
  };
  const requirement=line=>{
    const m=line.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]\r\n]+\])?(?=\s|[<>=!~@(;#]|$)(.*)$/);
    if(!m)return;
    const spec=m[2].split(/[;#]/,1)[0].replace(/\s+--hash=.*$/,"").trim();
    const pin=spec.match(/^\(?\s*==\s*([^\s(),]+)\s*\)?$/);
    add(m[1],pin?pin[1]:null);
  };
  if(base==="METADATA" || base==="PKG-INFO") {
    // Only headers identify the installed distribution; ignore long descriptions.
    const headers=text.split(/\r?\n\r?\n/,1)[0];
    const names=[...headers.matchAll(/^Name:[ \t]*(\S+)[ \t]*$/gmi)];
    const versions=[...headers.matchAll(/^Version:[ \t]*(\S+)[ \t]*$/gmi)];
    if(names.length>1 || versions.length>1)throw Error("duplicate metadata");
    if(names.length)add(names[0][1],versions[0]?.[1]||null);
    return packages;
  }
  if(base==="requirements.txt") {
    for(const line of text.replace(/\\\r?\n/g," ").split(/\r?\n/))requirement(line);
    return packages;
  }
  if(base==="Pipfile.lock") {
    const data=JSON.parse(text);
    if(!data || typeof data!=="object" || Array.isArray(data))throw Error("lock object required");
    for(const section of [data.default,data.develop]) {
      if(section==null)continue;
      if(typeof section!=="object" || Array.isArray(section))throw Error("lock section required");
      for(const [name,item] of Object.entries(section)) {
        const pin=typeof item?.version==="string"?item.version.match(/^==([^\s,]+)$/):null;
        add(name,pin?pin[1]:null);
      }
    }
    return packages;
  }
  let section="", packageName="", packageVersion=null;
  const finish=()=>{if(packageName)add(packageName,packageVersion);packageName="";packageVersion=null;};
  for(const statement of tomlParts(text,"\n")) {
    if(statement.startsWith("[")) {finish();section=statement;continue;}
    const pair=tomlPair(statement);if(!pair)continue;
    const [key,value]=pair;
    if(base==="pyproject.toml" && section==="[project]" && key==="dependencies") {
      if(!value.startsWith("[") || !value.endsWith("]"))throw Error("dependency array required");
      for(const item of tomlParts(value.slice(1,-1),","))requirement(tomlString(item));
    } else if(base==="pyproject.toml" && section==="[tool.poetry.dependencies]") {
      if(!["litellm","brotli","brotlicffi","pillow"].includes(key.toLowerCase()))continue;
      // Multiple Poetry constraints are unresolved here; keep scanning siblings.
      if(value.startsWith("[") && value.endsWith("]")) {add(key,null,true);continue;}
      let version=value;
      if(value.startsWith("{")) {
        if(!value.endsWith("}"))throw Error("inline table required");
        const fields=tomlParts(value.slice(1,-1),",").map(tomlPair);
        const versions=fields.filter(field=>field?.[0]==="version");
        if(versions.length>1)throw Error("duplicate version");
        if(!versions.length){add(key,null);continue;}
        version=versions[0][1];
      }
      const pin=tomlString(version).match(/^(?:==)?([^\s<>=!~^*,]+)$/);
      add(key,pin?pin[1]:null);
    } else if(base!=="pyproject.toml" && section==="[[package]]") {
      if(key==="name") {if(packageName)throw Error("duplicate name");packageName=tomlString(value);}
      if(key==="version") {if(packageVersion!==null)throw Error("duplicate version");packageVersion=tomlString(value);}
    }
  }
  finish();return packages;
}
function pythonMatch(text,base) {
  return pythonPackages(text,base).some(p=>p.name==="litellm" && p.version==="1.107.0");
}
function pythonVulnerability(item) {
  const {name,version}=item;
  if(name==="litellm" && item.poetryArray)return {
    severity:"medium",type:"litellm-october-version-review",source:SOURCES.litellm,
    message:"LiteLLM has multiple Poetry constraints; resolve each branch from trusted metadata before ruling out the compromised 1.107.0 release. Do not start Python or pip in a suspected environment. Markers are not evaluated; this is not proof of installation or execution."
  };
  if(!["brotli","brotlicffi","pillow"].includes(name))return null;
  const pillow=name==="pillow", cve=pillow?"CVE-2026-112900":"CVE-2026-111497";
  const source=pillow?SOURCES.pillow:SOURCES.brotli;
  const type=pillow?"pillow-ghostscript":"python-brotli-decoder";
  const guidance=pillow
    ?"Upgrade Pillow to 13.0.0 or later. The vulnerable path requires EPS processing through Ghostscript with an attacker-controlled filename; this scan does not assess that runtime path."
    :`Upgrade ${name} to ${name==="brotlicffi"?"1.2.1.0":"1.2.1"} or later. Exposure requires decoding attacker-controlled Brotli data. Updating Node does not update Python bindings.`;
  // This intentionally handles only final numeric releases. Other PEP 440 forms,
  // ranges and direct references need review, never a guessed safe verdict.
  const final=typeof version==="string" && version.match(/^v?(?:0!)?(\d+(?:\.\d+){1,3})$/i);
  const parts=final?final[1].split(".").map(Number):null;
  const compare=other=>{for(let i=0;i<Math.max(parts.length,other.length);i++){const d=(parts[i]||0)-(other[i]||0);if(d)return Math.sign(d);}return 0;};
  let review=!parts || parts.some(n=>!Number.isSafeInteger(n));
  // Upstream C-library backports exist, but these versions are not PyPI releases
  // in the dated advisory. Do not equate a custom binding's label with its C build.
  if(!review && name==="brotli" && compare([1,2,0])<0 &&
     ((parts[0]===1 && parts[1]===0 && compare([1,0,10])>=0) || (parts[0]===1 && parts[1]===1 && compare([1,1,1])>=0)))review=true;
  if(review)return {severity:"medium",type:type+"-version-review",source,
    message:`${name} is declared, but its exact upstream patch status for ${cve} needs review (unresolved, non-final, custom, or backported version). Inspect the resolved artifact and vendor fix evidence. ${guidance} Markers are not evaluated; this is not proof of installation or exploitation.`};
  const affected=pillow?compare([2,6,0])>=0 && compare([13,0,0])<0
    :compare([1,0,3])>=0 && compare(name==="brotlicffi"?[1,2,1,0]:[1,2,1])<0;
  if(!affected)return null;
  return {severity:pillow?"medium":"high",type:type+"-affected-version",source,
    message:`${name} ${parts.join(".")} metadata falls in the affected upstream range for ${cve}. ${guidance} Verify vendor backports and the deployed artifact. Markers are not evaluated; this is not proof of installation, malicious packaging, or exploitation.`};
}
function inspectFile(file, options={}) {
  if (!candidate(file)) return [];
  const base=path.basename(file), out=[];
  const emit=(severity,type,message,source=SOURCES.worm)=>out.push(finding(file,severity,type,message,source));
  try {
    const text=read(file,options.root);
    if (NPM_FILES.has(base)) {
      try {
        for (const match of npmMatches(text,base)) emit("critical","testmetest-exact-version",`Exact dependency metadata matches the reported malicious release ${match}. ${ORDER}`);
      } catch (error) {
        if (error instanceof SyntaxError && incidentalJson(file,options.root) && !/testmetest|\\[ux]/i.test(text))
          emit("low","october23-incidental-json","Malformed JSON in an incidental test/example/generated path was not parsed. It is not treated as an active dependency manifest; valid metadata in these paths is still inspected.");
        else throw error;
      }
    }
    if (PYTHON_FILES.has(base)) {
      const packages=pythonPackages(text,base);
      if(packages.some(p=>p.name==="litellm" && p.version==="1.107.0")) emit("critical","litellm-october-compromised-version",`LiteLLM 1.107.0 metadata matches the October 21 compromised release. ${LITELLM_ORDER}`,SOURCES.litellm);
      const seen=new Set();
      for(const item of packages) {
        const hit=pythonVulnerability(item);
        if(!hit || seen.has(hit.message))continue;
        seen.add(hit.message);emit(hit.severity,hit.type,hit.message,hit.source);
      }
    }
    if (base === "binding.gyp" && /<!\([^\r\n)]*\bnode\s+(?:\.\/)?index\.js\b[^\r\n)]*\)/.test(text)) emit("high","testmetest-gyp-loader-review",`Build metadata invokes an index.js loader using command expansion, consistent with the reported worm trigger. Legitimate builds can also execute commands; review context. ${ORDER}`);
    if (SERVICE_FILES.has(base)) {
      const correlated = /net-health-checker|\.local\/share\/runtimes|sync\.py|msync-3f7a|aiarmor\.website/.test(text);
      emit(correlated?"high":"medium","testmetest-persistence-review",`A reported persistence filename is present${correlated?" with related service or payload terms":"; filename alone is not proof of compromise"}. ${ORDER}`);
    }
    if (STARTUP_FILES.has(base)) {
      const correlated = /\bcook\b/.test(text) && /litellm\.dev|remote_code_loader|XWiA8gZNa7NcX2XRoAEb|letters9813/.test(text);
      if (correlated || base === "cook.pth") emit(correlated?"high":"medium","litellm-startup-review",`Python startup artifact requires review${correlated?"; reported payload terms co-occur":"; filename alone is not proof of compromise"}. ${LITELLM_ORDER}`,SOURCES.litellm);
    }
    if (CONTAINER_FILES.has(base)) {
      for (const match of text.matchAll(/^\s*(?:image:\s*|FROM\s+(?:--platform=\S+\s+)?)["']?((?:ghcr\.io\/berriai\/litellm(?:-database|-non_root)?|(?:docker\.io\/)?litellm\/litellm)(?::[^\s"'#]+|@sha256:[a-f0-9]{64})?)(?=[\s"'#]|$)/gmi)) {
        const image=match[1];
        const digest=image.match(/@sha256:([a-f0-9]{64})$/i)?.[1];
        const prefix=DIGEST_PREFIXES[image.split(/[:@]/,1)[0]];
        if (image.endsWith("@sha256:"+DIGEST)) emit("critical","litellm-container-digest",`Container configuration references the confirmed compromised image digest. This does not prove a pull or execution. ${LITELLM_ORDER}`,SOURCES.litellm);
        else if (prefix && digest?.startsWith(prefix)) emit("medium","litellm-container-digest-review",`Image digest matches a vendor-reported prefix for this variant. Verify the full digest and pull history; a prefix match alone is not an exact artifact identification. ${LITELLM_ORDER}`,SOURCES.litellm);
        else if (!image.includes(":") || /:(?:v1\.107\.0|latest|main-latest|main-stable)$/.test(image)) emit("medium","litellm-container-window-review","Review the image digest and pull history for October 21, 2026 (11:46–14:20 UTC). These tags (including implicit latest when no tag is given) were affected during that window; a tag now is not proof of compromise. Do not start the image to investigate.",SOURCES.litellm);
      }
    }
    if (base === "preinstall.js" && /https?:\/\/buildwithknexus\.xyz\/(?:check_m|check_w)\b/.test(text)) emit("high","forged-preinstall-endpoint","A reported forged-commit downloader endpoint occurs in an install-script candidate. Do not execute it; inspect source history and contain the environment if it ran. Text alone does not prove execution.",SOURCES.dropper);
  } catch (_) { out.push(incomplete(file)); }
  return out;
}
function safeRemovalGuidance(findings, fallback) {
  if (!findings.some(f=>/^testmetest-/.test(f.type||f.id||""))) return fallback;
  return {required:true, sequenceSensitive:true, activation:"not-assessed", firstAction:ORDER, instructionDestination:SOURCES.worm};
}
function entryBudget(value=100000) {
  if(!Number.isSafeInteger(value) || value<1 || value>10000000)throw Error("October 23 entry budget must be an integer from 1 to 10000000");
  return value;
}
function discover(root, options={}) {
  const files=[], findings=[], stack=[root]; let visited=0;
  const maxEntries = entryBudget(options.maxEntries);
  let discoveryIncomplete = false;
  const excluded=(options.excludePaths||[]).map(p=>path.resolve(p));
  while (stack.length) {
    if (++visited > maxEntries) { discoveryIncomplete = true; break; }
    const current=stack.pop();
    if (excluded.some(p=>within(p,current))) continue;
    try {
      const stat=fs.lstatSync(current);
      if (stat.isSymbolicLink()) { discoveryIncomplete = true; continue; }
      if (stat.isDirectory()) {
        if ([".git",".hg",".svn",".next","dist","build","coverage"].includes(path.basename(current))) continue;
        const dir = fs.opendirSync(current);
        try {
          let entry;
          while ((entry = dir.readSync())) {
            if (visited + stack.length >= maxEntries) { discoveryIncomplete = true; break; }
            stack.push(path.join(current,entry.name));
          }
        } finally { dir.closeSync(); }
      } else if (candidate(current)) files.push(current);
    } catch (_) { discoveryIncomplete = true; }
  }
  if (discoveryIncomplete) findings.push(incomplete(root));
  return {files,findings};
}
module.exports={inspectFile,entryBudget,discover,safeRemovalGuidance,npmMatches,pythonMatch,SOURCES,ORDER};
