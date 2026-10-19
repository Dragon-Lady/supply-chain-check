"use strict";
// Bounded static metadata inspection. No subprocesses, imports of targets or network calls.
const fs = require("fs");
const path = require("path");
const SOURCES = {
 malfex: "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/",
 apex: "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages",
 font: "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/",
 ghost: "https://opensourcemalware.com/blog/ghostaction-attack-escalates",
 airflow: "https://seclists.org/oss-sec/2026/q4/173",
 curl: "https://curl.se/docs/CVE-2026-92392.html",
 anydesk: "https://github.com/v12-security/pocs/tree/main/anydesk",
 harbor: "https://github.com/goharbor/harbor/security/advisories/GHSA-2phj-cp9f-qq6w"
};
const NPM = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]);
const PYTHON = new Set(["requirements.txt", "pyproject.toml", "uv.lock", "Pipfile.lock", "METADATA"]);
const EXACT = /^\d+\.\d+\.\d+$/;
const APICES = new Set(["@apexacc/cli", "@apexacc/audit"]);
const MAX_BYTES = 2 * 1024 * 1024;
function compare(a,b) { const x=a.split('.').map(Number),y=b.split('.').map(Number); for(let i=0;i<3;i++) if(x[i]!==y[i]) return x[i]<y[i]?-1:1; return 0; }
function curlAffected(v) {
 if(!EXACT.test(v)) return null;
 if(compare(v,"8.12.0")<0 || compare(v,"8.22.0")>0) return false;
 const [,minor,patch]=v.split('.').map(Number);
 return !((minor===14&&patch>=3)||(minor===16&&patch>=2)||(minor===20&&patch>=2));
}
function harborAffected(v) {
 return EXACT.test(v) && [["1.7.0","2.13.6"],["2.14.0","2.14.5"],["2.15.0","2.15.3"]].some(([min,max])=>compare(v,min)>=0&&compare(v,max)<0);
}
function packageRefs(text,base) {
 const refs=[];
 const add=(name,spec)=>{
  if(typeof spec!=="string") return;
  const alias=spec.match(/^npm:((?:@[^/\s]+\/)?[^@\s]+)@(.+)$/);
  refs.push(alias ? [alias[1],alias[2]] : [name,spec]);
 };
 if(base.endsWith('.json')) {
  const data=JSON.parse(text);
  if(!data || typeof data!=="object" || Array.isArray(data)) throw Error("invalid manifest");
  add(data.name,data.version);
  for(const group of ['dependencies','devDependencies','optionalDependencies','peerDependencies'])
   for(const [name,spec] of Object.entries(data[group]||{})) add(name,spec);
  for(const [key,value] of Object.entries(data.packages||{})) {
   const name=value?.name || key.split('node_modules/').pop();
   add(name,value?.version);
  }
  const pending=[data.dependencies]; let count=0;
  while(pending.length && count++<100000) {
   const deps=pending.pop(); if(!deps||typeof deps!=="object") continue;
   for(const [name,value] of Object.entries(deps)) {
    if(value && typeof value==='object') { add(name,value.version); if(value.dependencies) pending.push(value.dependencies); }
   }
  }
  if(pending.length) throw Error("metadata limit");
 } else if(base==='pnpm-lock.yaml') {
  for(const m of text.matchAll(/^\s*['"]?\/?(imgdecode|@apexacc\/(?:cli|audit))(?:@|\/)([^\s:'"()]+)(?:\([^\r\n]*\))?['"]?:/gm)) add(m[1],m[2]);
 } else if(base==='yarn.lock') {
  for(const block of text.split(/(?=^\S)/m)) {
   const header=block.split(/\r?\n/)[0];
   const version=block.match(/^\s+version\s*:?[ \t]+["']?([^\s"']+)/m)?.[1];
   for(const name of ['imgdecode',...APICES]) {
    const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    if(new RegExp('(?:^|[,\\s"\'])(?:[^,"\'\\s]+@npm:)?'+escaped+'@').test(header)) add(name,version||'unresolved');
   }
  }
 }
 return refs;
}
function parseTaskJson(text) {
 // Preserve strings while removing JSONC comments and trailing commas.
 let clean='', quoted=false, escaped=false;
 for(let i=0;i<text.length;i++) {
  const c=text[i];
  if(quoted) {clean+=c;if(escaped) escaped=false;else if(c==='\\') escaped=true;else if(c==='"') quoted=false;continue;}
  if(c==='"') {quoted=true;clean+=c;continue;}
  if(c==='/'&&text[i+1]==='/') {while(i<text.length&&text[i]!=='\n') i++;clean+='\n';continue;}
  if(c==='/'&&text[i+1]==='*') {const end=text.indexOf('*/',i+2);if(end<0) throw Error('comment');i=end+1;clean+=' ';continue;}
  clean+=c;
 }
 let normalized='';quoted=false;escaped=false;
 for(let i=0;i<clean.length;i++) {
  const c=clean[i];
  if(quoted) {normalized+=c;if(escaped) escaped=false;else if(c==='\\') escaped=true;else if(c==='"') quoted=false;continue;}
  if(c==='"') quoted=true;
  if(c===',' && /^[\s]*[}\]]/.test(clean.slice(i+1))) continue;
  normalized+=c;
 }
 return JSON.parse(normalized);
}

function inspectText(file,text) {
 const base=path.basename(file), out=[];
 const add=(severity,type,message,source)=>out.push({severity,type,path:file,message:message+' '+SOURCES[source]});
 if(NPM.has(base)) for(const [name,spec] of packageRefs(text,base)) {
  if(name==='imgdecode') {
   const exact=EXACT.test(spec);
   if(exact && /^1\.0\.[0-3]$/.test(spec)) add('critical','malfex-imgdecode-version',`Exact imgdecode ${spec} metadata matches reported malicious releases. Native Windows code can run on import; inventory is not proof of execution.`, 'malfex');
   else if(!exact) add('medium','malfex-imgdecode-review','imgdecode uses an unresolved version; check the resolved artifact against reported versions 1.0.0 through 1.0.3.','malfex');
  }
  if(APICES.has(name)) add('medium','apex-package-review',`${name} is a reported malicious package identity. Exact malicious versions are not pinned here; review provenance and resolved artifacts. No Linux execution or compromise is inferred.`, 'apex');
 }
 if(PYTHON.has(base)) {
  // Exact requirement pins and package records only; never borrow a nearby package's version.
  const refs=[];
  for(const m of text.matchAll(/(?:^|[\s"'])apache[-_]airflow[-_]providers[-_](ssh|sftp)(?:\[[^\]\r\n]*\])?\s*==\s*(\d+\.\d+\.\d+)(?=[\s"';,#]|$)/gm)) refs.push([m[1],m[2]]);
  if(base==='Pipfile.lock') {
   const obj=JSON.parse(text);
   for(const group of ['default','develop']) for(const [name,item] of Object.entries(obj[group]||{})) {
    const m=name.match(/^apache[-_]airflow[-_]providers[-_](ssh|sftp)$/);
    const v=item?.version?.match(/^==(\d+\.\d+\.\d+)$/)?.[1]; if(m&&v) refs.push([m[1],v]);
   }
  }
  if(base==='uv.lock') for(const block of text.split(/^\[\[package\]\]\s*$/m)) {
   const name=block.match(/^name\s*=\s*"apache[-_]airflow[-_]providers[-_](ssh|sftp)"\s*$/m)?.[1];
   const version=block.match(/^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$/m)?.[1]; if(name&&version) refs.push([name,version]);
  }
  if(base==='METADATA') {
   const name=text.match(/^Name:\s*apache[-_]airflow[-_]providers[-_](ssh|sftp)\s*$/mi)?.[1];
   const version=text.match(/^Version:\s*(\d+\.\d+\.\d+)\s*$/m)?.[1]; if(name&&version) refs.push([name.toLowerCase(),version]);
  }
  for(const [provider,version] of refs) if(compare(version,'7.0.0')<0) add('medium','airflow-host-key-version',`Airflow ${provider} provider ${version} predates 7.0.0 host-key verification fixes (CVE-2026-94134${provider==='sftp'?' / CVE-2026-94135, including async SFTP':''}). Verify every connection's host-key settings; a pin alone does not establish runtime exposure.`, 'airflow');
  if(/apache[-_]airflow[-_]providers[-_](ssh|sftp)/.test(text)&&refs.length===0) add('medium','airflow-provider-review','Airflow SSH/SFTP dependency is not an exact supported pin. Resolve its installed provider version and verify host-key configuration.','airflow');
 }
 if(/\.(?:py|json|cfg|ini|ya?ml)$/.test(base) && /airflow|SFTPHook|SSHHook|SFTPTrigger/.test(text)) {
  if(/no_host_key_check["']?\s*[:=]\s*(?:["']?true\b|True\b)|known_hosts\s*=\s*None\b/.test(text)) add('medium','airflow-host-key-disabled','Airflow-context text explicitly disables host-key verification. Review the referenced connection or async path; this is static evidence, not runtime confirmation.','airflow');
  if(/no_host_key_check["']?\s*[:=]\s*(?:["']?false\b|False\b)/.test(text)) add('info','airflow-host-key-opt-in','An explicit host-key verification opt-in appears in Airflow-context text. Verify the trusted key and all sync/async connections; this does not suppress version findings.','airflow');
 }
 if(base==='tasks.json') {
  const data=parseTaskJson(text);
  for(const task of Array.isArray(data.tasks)?data.tasks:[]) {
   const command=[task.command,...(Array.isArray(task.args)?task.args:[])].filter(x=>typeof x==='string').join(' ');
   if(task.runOptions?.runOn==='folderOpen' && /(?:^|\s|\/)node(?:\.exe)?["']?\s+/.test(command) && /(?:^|[\s/])fa-solid-400\.woff2(?:["')]|\s|$)/.test(command))
    add('high','vscode-autorun-fake-font-task','A folder-open task runs a reported fake-font filename through Node. Review before opening the project; an ordinary font asset alone is not a match.','font');
  }
 }
 if(/\.(?:ya?ml|js|cjs|mjs|sh|ps1|json)$/.test(base)) {
  for(const raw of text.matchAll(/https?:\/\/[^\s"'<>`\\]+/g)) {
   let url; try {url=new URL(raw[0]);} catch {continue;}
   if(['193.32.204.199','my-github.com'].includes(url.hostname)) add('medium','ghostaction-collector-review','Static content references infrastructure discussed in the GhostAction report. Domain operator attribution and execution remain unconfirmed.','ghost');
   if(url.hostname==='vrf.apexaccs.org' && url.pathname==='/api/v1/vrf') add('medium','apex-verification-endpoint','Static content references the reported Apex command-verification endpoint; inspect provenance without contacting it.','apex');
  }
 }
 if(/^(?:Dockerfile|(?:docker-)?compose\.ya?ml|harbor\.ya?ml)$/.test(base) || /\.ya?ml$/.test(base)) {
  for(const m of text.matchAll(/(?:^|[\s"'])(?:(?:docker\.io|goharbor\.io)\/)?goharbor\/(?:harbor-core|harbor-jobservice):v?(\d+\.\d+\.\d+)(?=[\s"'@]|$)/gm))
   if(harborAffected(m[1])) add('high','harbor-webhook-ssrf-version',`Harbor image tag ${m[1]} is in GHSA-2phj-cp9f-qq6w's affected ranges. Exposure requires untrusted project admins and jobservice access to internal destinations. Verify the deployed digest and upgrade the affected branch.`, 'harbor');
 }
 if(base==='status' && /(?:^|\/)var\/lib\/dpkg\/status$/.test(file.replace(/\\/g,'/'))) for(const record of text.split(/\r?\n\s*\r?\n/)) {
  if(!/^Status:\s*install ok installed\s*$/m.test(record)) continue;
  const name=record.match(/^Package:\s*(\S+)/m)?.[1], raw=record.match(/^Version:\s*(\S+)/m)?.[1];
  const version=raw?.match(/^(?:\d+:)?(\d+\.\d+\.\d+)(?:[-+~].*)?$/)?.[1]; if(!version) continue;
  if(/^(?:curl|libcurl[\w-]*)$/.test(name||'') && curlAffected(version)) add('medium','curl-http2-package-review',`Installed ${name} upstream version ${version} falls in CVE-2026-92392's affected range. Distribution backports and HTTP/2 capability are not resolved; verify the vendor package advisory before treating it as vulnerable.`, 'curl');
  if(name==='anydesk' && version==='8.0.2') add('high','anydesk-linux-version','Installed AnyDesk Linux 8.0.2 matches the researcher-tested version; 8.0.3 fixes the reported issue. Listener reachability and exploitation are not assessed.','anydesk');
  else if(name==='anydesk'&&compare(version,'8.0.3')<0) add('medium','anydesk-linux-review','Older AnyDesk Linux inventory needs review. The research tested 8.0.2 and identified 8.0.3 as fixed; other versions are not confirmed here.','anydesk');
 }
 return [...new Map(out.map(f=>[f.type+'\0'+f.message,f])).values()];
}
function candidate(file) {
 const base=path.basename(file);
 return NPM.has(base)||PYTHON.has(base)||base==='Dockerfile'||base==='status'||/\.(?:ya?ml|js|cjs|mjs|sh|ps1|json|py|cfg|ini)$/.test(base);
}
function inspectFile(file) {
 if(!candidate(file)) return [];
 let fd;
 try {
  if(fs.lstatSync(file).isSymbolicLink()) throw Error('symlink');
  fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=fs.fstatSync(fd); if(!before.isFile()||before.size>MAX_BYTES) throw Error('size');
  const buffer=Buffer.alloc(before.size); let offset=0;
  while(offset<buffer.length) {const n=fs.readSync(fd,buffer,offset,buffer.length-offset,offset);if(!n) throw Error('changed');offset+=n;}
  const after=fs.fstatSync(fd); if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs) throw Error('changed');
  return inspectText(file,buffer.toString('utf8'));
 } catch {
  return [{severity:'medium',type:'october-review-incomplete',path:file,message:'Candidate could not be read or parsed within the 2 MiB static inspection limit. Coverage is incomplete; contents and error details are withheld.'}];
 } finally {if(fd!==undefined) fs.closeSync(fd);}
}
module.exports={inspectFile,inspectText,curlAffected,harborAffected};
