"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const {test} = require("node:test");
const detector = require("../src/october23");
const pkg = require("../package.json");
const linux = pkg.name === "linux-supply-chain-guard";
const scanner = require(linux ? "../src/checker" : "../src/scanner");
function fixture(fn) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),"oct23-review-")),home=path.join(root,"home/fixture");
 fs.mkdirSync(home,{recursive:true});
 const write=(name,text)=>{const f=path.join(home,name);fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,text);return f;};
 try {fn({root,home,write,scan:()=>linux?scanner.scanHost({targetRoot:root,homePath:home,kernelRelease:"9.0.0",architecture:"x64"}):scanner.scanTarget(home)});} finally {fs.rmSync(root,{recursive:true,force:true});}
}
const ids=r=>r.findings.map(f=>f.type||f.id);
test("exact npm metadata including aliases and nested locks; decoys/ranges/descriptions stay clear",()=>{
 const n="event-bus-lite-testmetest",v="0.0.1";
 for(const data of [{name:n,version:v},{dependencies:{[n]:v}},{devDependencies:{alias:`npm:${n}@${v}`}},{packages:{[`node_modules/${n}`]:{version:v}}},{dependencies:{outer:{dependencies:{[n]:{version:v}}}}}]) assert.equal(detector.npmMatches(JSON.stringify(data),"package.json").length,1);
 for(const data of [{name:n,version:"1.0.0"},{dependencies:{[n]:"^0.0.1"}},{description:`${n}@${v}`},{dependencies:{[n]:"0.0.10"}},{packages:{"node_modules/other":{version:v}}}]) assert.deepEqual(detector.npmMatches(JSON.stringify(data),"package.json"),[]);
 assert.equal(detector.npmMatches(`${n}@^0.0.0:\n  version "${v}"\n`,"yarn.lock").length,1);
 assert.equal(detector.npmMatches(`packages:\n  '${n}@${v}': {}\n`,"pnpm-lock.yaml").length,1);
});
test("LiteLLM exact evidence stays within supported Python metadata fields",()=>{
 for(const [base,text]of [["requirements.txt","litellm==1.107.0\n"],["requirements.txt","litellm[proxy]==1.107.0 ; python_version > '3.10'\n"],["METADATA","Name: litellm\nVersion: 1.107.0\n"],["uv.lock","[[package]]\nname = 'litellm'\nversion = '1.107.0'\n"],["pyproject.toml","[project]\ndependencies = [\n 'litellm==1.107.0'\n]\n"],["Pipfile.lock",JSON.stringify({default:{litellm:{version:"==1.107.0"}}})]]) assert(detector.pythonMatch(text,base),base);
 for(const [base,text]of [["requirements.txt","litellm==1.106.2\n"],["requirements.txt","litellm==1.107.00\n"],["requirements.txt","# litellm==1.107.0\n"],["requirements.txt","litellm>=1.107.0\n"],["METADATA","Name: other\nVersion: 1.107.0\n"],["pyproject.toml","[project]\ndescription = 'litellm==1.107.0'\n"],["uv.lock","[[package]]\nname = 'litellm'\nversion = '1.106.2'\n[[package]]\nname = 'other'\nversion = '1.107.0'\n"]]) assert(!detector.pythonMatch(text,base),base);
});
test("default scan sees exact malicious package and prioritizes wiper ordering",()=>fixture(({write,scan})=>{
 write("project/package.json",JSON.stringify({dependencies:{"event-bus-lite-testmetest":"0.0.1"}}));
 const r=scan();assert(ids(r).includes("testmetest-exact-version"));assert(r.safeRemovalGuidance.required);assert(r.safeRemovalGuidance.sequenceSensitive);assert.match(r.safeRemovalGuidance.firstAction,/before revoking/);
 if(r.guidance)assert.match(r.guidance.join(" "),/before revoking/);
 if(pkg.name==="herewegoagain-incident-scanner") {const p=require("../src/remediation").buildRemediationPlan(r);assert(p.hasDeadManSwitch);assert(p.items.some(x=>x.id==="testmetest-ordered-response"));}
}));
test("build trigger is active by default and is never executed",()=>fixture(({write,scan})=>{
 write("node_modules/fixture/package.json",JSON.stringify({name:"fixture",version:"1.0.0"}));
 write("node_modules/fixture/binding.gyp",JSON.stringify({targets:[{sources:["<!(node index.js 1>/dev/null 2>/dev/null; echo stub.c)"]}]}));
 write("node_modules/fixture/index.js","throw new Error('fixture must never execute');\n");
 assert(ids(scan()).includes("testmetest-gyp-loader-review"));
}));
test("known service filenames require review without claiming activation",()=>fixture(({write,scan})=>{
 write(".config/systemd/user/net-health-checker.service","[Service]\nExecStart=/usr/bin/false\n");
 const r=scan();assert(ids(r).includes("testmetest-persistence-review"));assert.equal(r.safeRemovalGuidance.activation,"not-assessed");
}));
test("installed LiteLLM metadata inside a virtual environment is discovered",()=>fixture(({write,scan})=>{
 write("project/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA","Name: litellm\nVersion: 1.107.0\n");
 assert(ids(scan()).includes("litellm-october-compromised-version"));
}));
test("generic sitecustomize is not malware; named hook requests static review",()=>fixture(({write,home})=>{
 const f=write("sitecustomize.py","# ordinary site customization\n");assert.deepEqual(detector.inspectFile(f,{root:home}),[]);
 const hook=write("cook.pth","# inert test\n");assert.equal(detector.inspectFile(hook,{root:home})[0].severity,"medium");
}));
test("container tag review is distinct from a compromised digest",()=>fixture(({write,home})=>{
 const f=write("Dockerfile","FROM ghcr.io/berriai/litellm:latest\n");let r=detector.inspectFile(f,{root:home});assert.equal(r[0].type,"litellm-container-window-review");assert.equal(r[0].severity,"medium");
 fs.writeFileSync(f,"FROM ghcr.io/berriai/litellm@sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e\n");r=detector.inspectFile(f,{root:home});assert.equal(r[0].type,"litellm-container-digest");
 fs.writeFileSync(f,"FROM other/litellm:latest\n# image: ghcr.io/berriai/litellm:latest\n");assert.deepEqual(detector.inspectFile(f,{root:home}),[]);
}));
test("malformed and oversized candidates report incomplete coverage without disclosing content",()=>fixture(({write,home,scan})=>{
 const canary="fixture-private-value";const f=write("package.json",'{"name":"'+canary+'"');let r=detector.inspectFile(f,{root:home});assert.equal(r[0].type,"october23-coverage-incomplete");assert(!JSON.stringify(r).includes(canary));assert.equal(scan().coverage.complete,false);
 fs.writeFileSync(f," ".repeat(32*1024*1024+1));r=detector.inspectFile(f,{root:home});assert.equal(r[0].type,"october23-coverage-incomplete");
}));
test("symlink candidates and out-of-root parents are not read", {skip:process.platform === "win32"},()=>fixture(({root,home,write})=>{
 const external=path.join(root,"external");fs.mkdirSync(external);fs.writeFileSync(path.join(external,"package.json"),'{"dependencies":{"event-bus-lite-testmetest":"0.0.1"}}');
 fs.symlinkSync(external,path.join(home,"linked"));assert.equal(detector.inspectFile(path.join(home,"linked/package.json"),{root:home})[0].type,"october23-coverage-incomplete");
 fs.symlinkSync(path.join(external,"package.json"),path.join(home,"package.json"));assert.equal(detector.inspectFile(path.join(home,"package.json"),{root:home})[0].type,"october23-coverage-incomplete");
 const d=detector.discover(home);assert.equal(d.files.length,0);assert(d.findings.length>=1);
}));
test("discovery budgets and exclusions remain visible",()=>fixture(({home,write})=>{
 write("skip/package.json","{}");write("other/package.json","{}");
 assert.equal(detector.discover(home,{maxEntries:1}).findings[0].type,"october23-coverage-incomplete");
 assert(!detector.discover(home,{excludePaths:[path.join(home,"skip")]}).files.some(f=>f.includes("/skip/")));
}));

test("direct candidate targets are readable without expanding their scope",()=>fixture(({write})=>{
 const file=write("package.json",JSON.stringify({dependencies:{"event-bus-lite-testmetest":"0.0.1"}}));
 assert.equal(detector.inspectFile(file,{root:file})[0].type,"testmetest-exact-version");
 if(!linux) {const r=scanner.scanTarget(file);assert(ids(r).includes("testmetest-exact-version"));assert.equal(r.coverage.complete,true);}
}));
test("nested TOML metadata cannot supply another package's version",()=>{
 assert.equal(detector.pythonMatch('[[package]]\nname = "litellm"\nversion = "1.106.2"\n[package.metadata]\nversion = "1.107.0"\n',"uv.lock"),false);
});

test("incidental malformed fixtures remain informational but relevant text is not dismissed",()=>fixture(({write,home})=>{
 const f=write("test/fixtures/broken/package.json","{invalid");
 assert.equal(detector.inspectFile(f,{root:home})[0].type,"october23-incidental-json");
 fs.writeFileSync(f,'{"event-bus-lite-testmetest":"0.0.1"');
 assert.equal(detector.inspectFile(f,{root:home})[0].type,"october23-coverage-incomplete");
 fs.writeFileSync(f,JSON.stringify({dependencies:{"event-bus-lite-testmetest":"0.0.1"}}));
 assert.equal(detector.inspectFile(f,{root:home})[0].type,"testmetest-exact-version");
}));

test("review: hash-pinned requirements continuations detect exact LiteLLM versions",()=>fixture(({write,scan})=>{
 write("requirements.txt", 'litellm[proxy]==1.107.0 \\\n    --hash=sha256:'+'a'.repeat(64)+' \\\n    --hash=sha256:'+'b'.repeat(64)+'\n');
 assert(ids(scan()).includes("litellm-october-compromised-version"));
 for(const text of ['litellm==1.107.00 \\\n --hash=sha256:abc\n','# litellm==1.107.0 \\\n --hash=sha256:abc\n','other==1.107.0 \\\n --hash=sha256:abc\n']) assert.equal(detector.pythonMatch(text,"requirements.txt"),false);
}));
test("review: pyproject extras and prior extras do not truncate dependency arrays",()=>fixture(({write,scan})=>{
 const file=write("pyproject.toml","");
 for(const dependencies of ['["litellm[proxy]==1.107.0"]','["uvicorn[standard]>=0.30", "litellm==1.107.0"]',"[\n 'httpx[http2]', # array comment ]\n 'litellm[proxy]==1.107.0; python_version >= \\\"3.10\\\"',\n]"]){
  // The first two examples reproduce the review verbatim; use ordinary TOML quotes for the marker case.
  const source='[project]\ndependencies = '+dependencies.replace(/\\"/g,'"')+'\n';
  fs.writeFileSync(file,source);assert(ids(scan()).includes("litellm-october-compromised-version"),source);
 }
 for(const text of ['[project]\ndescription = "litellm==1.107.0"\ndependencies = ["httpx[http2]"]','[project]\ndependencies = ["litellm[proxy]==1.107.00"]','[project]\ndependencies = ["httpx"] # "litellm==1.107.0"','[project]\ndescription = """\n[project]\ndependencies = [\'litellm==1.107.0\']\n"""']) assert.equal(detector.pythonMatch(text,"pyproject.toml"),false,text);
}));
test("review: Poetry inline version tables stay scoped to the LiteLLM entry",()=>fixture(({write,scan})=>{
 const file=write("pyproject.toml","");
 for(const value of ['{version = "1.107.0", extras = ["proxy"]}',"{extras = ['proxy'], version = '==1.107.0'}",'"1.107.0" # pinned']) {
  fs.writeFileSync(file,'[tool.poetry.dependencies]\nlitellm = '+value+'\n');assert(ids(scan()).includes("litellm-october-compromised-version"),value);
 }
 for(const value of ['{version = "1.106.2", extras = ["proxy"]}','{version = "^1.107.0"}','{note = "version = \'1.107.0\'"}']) assert.equal(detector.pythonMatch('[tool.poetry.dependencies]\nlitellm = '+value+'\n',"pyproject.toml"),false);
 assert.equal(detector.pythonMatch('[tool.poetry.dependencies]\nother = {version = "1.107.0"}\nlitellm = "1.106.2"',"pyproject.toml"),false);
}));
test("review: untagged LiteLLM images are floating tags, not exact compromised artifacts",()=>fixture(({write,home,scan})=>{
 const file=write("compose.yaml",'services:\n  proxy:\n    image: ghcr.io/berriai/litellm\n');
 assert(ids(scan()).includes("litellm-container-window-review"));
 for(const name of ['ghcr.io/berriai/litellm','ghcr.io/berriai/litellm-database','ghcr.io/berriai/litellm-non_root','litellm/litellm','docker.io/litellm/litellm']) {
  fs.writeFileSync(file,'image: "'+name+'" # floating\n');const hit=detector.inspectFile(file,{root:home});assert.equal(hit[0].type,"litellm-container-window-review");assert.equal(hit[0].severity,"medium");
 }
 for(const name of ['ghcr.io/berriai/litellm-other','other/litellm','ghcr.io/berriai/litellm:1.106.2']) {fs.writeFileSync(file,'image: '+name+'\n');assert.deepEqual(detector.inspectFile(file,{root:home}),[]);}
}));
test("review: vendor digest prefixes request review only for their image variants",()=>fixture(({write,home,scan})=>{
 const file=write("Dockerfile","");
 for(const [variant,prefix] of [['database','c00f9d92c427'],['non_root','7b00e91cd2fe']]) {
  // Synthetic suffix: the advisory publishes only these prefixes, not full digests.
  fs.writeFileSync(file,'FROM ghcr.io/berriai/litellm-'+variant+'@sha256:'+prefix+'0'.repeat(52)+'\n');
  assert(ids(scan()).includes("litellm-container-digest-review"));
  const hit=detector.inspectFile(file,{root:home})[0];assert.equal(hit.severity,"medium");assert.match(hit.message,/prefix/);assert.doesNotMatch(hit.message,/confirmed compromised image digest/);
 }
 for(const image of ['ghcr.io/berriai/litellm-database@sha256:7b00e91cd2fe'+'0'.repeat(52),'other/litellm-database@sha256:c00f9d92c427'+'0'.repeat(52),'ghcr.io/berriai/litellm-non_root@sha256:'+'0'.repeat(64)]) {fs.writeFileSync(file,'FROM '+image+'\n');assert.deepEqual(detector.inspectFile(file,{root:home}),[]);}
}));

test("Python advisory boundaries distinguish affected, patched and unresolved versions",()=>fixture(({write,home})=>{
 const file=write("requirements.txt","");
 const cases=[
  ["Brotli","1.0.2",null],["brotli","1.0.3","affected"],["brotli","1.0.9","affected"],
  ["brotli","1.0.10","review"],["brotli","1.1.0","affected"],["brotli","1.1.1","review"],
  ["brotli","1.2.0","affected"],["brotli","1.2.1",null],["brotli","1.3.0",null],
  ["brotlicffi","1.0.9.2","affected"],["brotlicffi","1.2.0.2","affected"],["brotlicffi","1.2.1.0",null],
  ["Pillow","2.5.0",null],["pillow","2.6.0","affected"],["pillow","12.3.0","affected"],
  ["pillow","13.0.0",null],["pillow","13.0",null],["pillow","14.0.0",null],
  ["pillow","13.0.0rc1","review"],["brotli","1.2.1.dev0","review"],
  ["pillow","12.3.0+vendor.1","review"],["brotli","1.2.*","review"],
  ["pillow","v12.03.0","affected"],["brotli","0!1.2.0","affected"],
  ["pillow","1!12.3.0","review"],["pillow","99999999999999999.0","review"]
 ];
 for(const [name,version,status] of cases) {
  fs.writeFileSync(file,`${name}==${version}\n`);
  const hits=detector.inspectFile(file,{root:home});
  if(status===null)assert.deepEqual(hits,[],`${name} ${version}`);
  else {assert.equal(hits.length,1,`${name} ${version}`);assert.match(hits[0].type,status==="review"?/-version-review$/:/-affected-version$/);assert.equal(hits[0].evidence.activation,"not-assessed");}
 }
}));
test("Brotli and Pillow are found across supported Python metadata formats",()=>fixture(({write,home})=>{
 const cases=[
  ["requirements.txt",'Brotli==1.2.0 \\\n --hash=sha256:'+'a'.repeat(64)+'\nPillow[extra]==12.3.0 ; python_version < "1.0"\n'],
  ["pyproject.toml",'[project]\ndependencies = ["httpx[http2]", "Brotli==1.2.0", "Pillow[extra] (==12.3.0)"]\n'],
  ["pyproject.toml",'[tool.poetry.dependencies]\nBrotli = "1.2.0"\nPillow = {version = "==12.3.0", extras = ["extra"]}\n'],
  ["uv.lock",'[[package]]\nname = "Brotli"\nversion = "1.2.0"\n[[package]]\nname = "Pillow"\nversion = "12.3.0"\n'],
  ["poetry.lock","[[package]]\nname='brotli'\nversion='1.2.0'\n[package.files]\nother=[]\n[[package]]\nname='pillow'\nversion='12.3.0'\n"],
  ["Pipfile.lock",JSON.stringify({default:{Brotli:{version:"==1.2.0"}},develop:{Pillow:{version:"==12.3.0"}}})]
 ];
 for(const [base,text] of cases) {
  const hits=detector.inspectFile(write("formats/"+base,text),{root:home});
  assert.deepEqual(hits.map(h=>h.type).sort(),["pillow-ghostscript-affected-version","python-brotli-decoder-affected-version"],base);
 }
 for(const base of ["METADATA","PKG-INFO"]) {
  const hit=detector.inspectFile(write("installed/"+base,"Metadata-Version: 2.4\nName: brotlicffi\nVersion: 1.2.0.2\n\nlong description\n"),{root:home});
  assert.equal(hit[0].type,"python-brotli-decoder-affected-version");
 }
}));
test("unresolved Python declarations request review without leaking source values",()=>fixture(({write,home})=>{
 const syntheticReference="fixture-private-reference";
 for(const [base,text] of [
  ["requirements.txt",`brotli>=1.2.0\npillow @ https://example.invalid/${syntheticReference}.whl\n`],
  ["pyproject.toml",'[project]\ndependencies=["brotli", "pillow~=12.0"]'],
  ["pyproject.toml",`[tool.poetry.dependencies]\nbrotli={git="https://example.invalid/${syntheticReference}"}\npillow="^12.0"`],
  ["Pipfile.lock",JSON.stringify({default:{brotli:{version:"*"},pillow:{path:syntheticReference}}})]
 ]) {
  const hits=detector.inspectFile(write("unresolved/"+base,text),{root:home});
  assert.equal(hits.length,2,base);assert(hits.every(h=>h.type.endsWith("-version-review")));assert(!JSON.stringify(hits).includes(syntheticReference));
 }
}));
test("Python advisory decoys, unrelated packages and metadata descriptions stay clear",()=>fixture(({write,home})=>{
 for(const [base,text] of [
  ["requirements.txt","# pillow==12.3.0\nbrotli-helper==1.2.0\nother==12.3.0\n--index-url https://example.invalid/pillow==12.3.0\n"],
  ["pyproject.toml",'[project]\ndescription="pillow==12.3.0"\ndependencies=["brotli-helper==1.2.0"]\n[tool.example]\npillow="12.3.0"'],
  ["uv.lock",'[[package]]\nname="pillow"\nversion="13.0.0"\n[package.metadata]\nversion="12.3.0"\n[[package]]\nname="other"\nversion="1.2.0"'],
  ["METADATA","Name: other\nVersion: 1.2.0\n\nName: pillow\nVersion: 12.3.0\n"],
  ["package.json",JSON.stringify({dependencies:{brotli:"1.2.0",pillow:"12.3.0"}})]
 ])assert.deepEqual(detector.inspectFile(write("decoys/"+base,text),{root:home}),[],base);
}));
test("malformed Python metadata is incomplete rather than silently cleared",()=>fixture(({write,home})=>{
 for(const [base,text] of [
  ["pyproject.toml",'[project]\ndependencies=["pillow==12.3.0"'],
  ["Pipfile.lock",'{"default":{"pillow":'],
  ["uv.lock",'[[package]]\nname="pillow"\nversion="12.3.0"\nversion="13.0.0"'],
  ["METADATA","Name: pillow\nVersion: 12.3.0\nVersion: 13.0.0\n"]
 ])assert.equal(detector.inspectFile(write("broken/"+base,text),{root:home})[0].type,"october23-coverage-incomplete",base);
}));
test("default reports include both advisories without executing Python or activating worm response",()=>fixture(({write,scan})=>{
 write("requirements.txt","brotli==1.2.0\nPillow==12.3.0\n");
 write("sitecustomize.py","throw new Error('must never execute inspected Python');\n");
 const r=scan();
 for(const type of ["python-brotli-decoder-affected-version","pillow-ghostscript-affected-version"])assert(ids(r).includes(type));
 assert(!r.safeRemovalGuidance?.sequenceSensitive);
 for(const f of r.findings.filter(f=>/^(python-brotli-decoder|pillow-ghostscript)/.test(f.type||f.id||""))) {
  assert.match(f.message||f.title,/not proof/);assert.doesNotMatch(f.message||f.title,/rotate|revoke|delete/);
 }
}));

test("Poetry constraint arrays preserve other findings and request version review",()=>fixture(({write,home,scan})=>{
 const file=write("pyproject.toml","");
 const array='[\n  {version = "^9", python = "<3.8"},\n  {version = "^10", python = ">=3.8"},\n]';
 for(const name of ["pillow","brotli","brotlicffi","litellm"]) {
  // Reproduce the reported Poetry-only case; use a project pin when the array
  // itself is LiteLLM so both declarations remain legal TOML.
  const pin=name==="litellm"?'[project]\ndependencies = ["litellm==1.107.0"]\n':'litellm = "1.107.0"\n';
  const forms=name==="litellm"
   ?[pin+'[tool.poetry.dependencies]\nlitellm = '+array, '[tool.poetry.dependencies]\nlitellm = '+array+'\n'+pin]
   :['[tool.poetry.dependencies]\npython = "^3.10"\n'+pin+name+' = '+array, '[tool.poetry.dependencies]\n'+name+' = '+array+'\n'+pin];
  for(const text of forms) {
   fs.writeFileSync(file,text+'\n');
   const hits=detector.inspectFile(file,{root:home});
   assert(hits.some(h=>h.type==="litellm-october-compromised-version" && h.severity==="critical"),name);
   const review=hits.find(h=>h.type.endsWith("-version-review"));assert(review,name);assert.equal(review.severity,"medium");
   assert(!hits.some(h=>h.type==="october23-coverage-incomplete"),name);
   assert(ids(scan()).includes("litellm-october-compromised-version"),name);
  }
 }
 fs.writeFileSync(file,'[tool.poetry.dependencies]\nlitellm = '+array+'\n');
 const hits=detector.inspectFile(file,{root:home});
 assert.equal(hits.length,1);assert.equal(hits[0].type,"litellm-october-version-review");
 assert.equal(hits[0].evidence.activation,"not-assessed");
 fs.writeFileSync(file,'[tool.poetry.dependencies]\npillow = [\n{version="^9"}\n');
 assert.equal(detector.inspectFile(file,{root:home})[0].type,"october23-coverage-incomplete");
}));
