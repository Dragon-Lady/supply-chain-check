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
