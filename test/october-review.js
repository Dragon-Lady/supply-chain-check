"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {inspectText,inspectFile,curlAffected,harborAffected}=require('../src/october-review');
const has=(file,text,id)=>inspectText(file,text).some(f=>f.type===id);
const json=JSON.stringify;
for(const version of ['1.0.0','1.0.1','1.0.2','1.0.3']) for(const kind of ['manifest','installed','v1','v3','pnpm','yarn','alias']) test(`MALFEX ${version} ${kind}`,()=>{
 let file='package.json',text;
 if(kind==='manifest') text=json({dependencies:{imgdecode:version}});
 if(kind==='installed') text=json({name:'imgdecode',version});
 if(kind==='v1') {file='package-lock.json';text=json({dependencies:{other:{version:'2.0.0',dependencies:{imgdecode:{version}}}}});}
 if(kind==='v3') {file='package-lock.json';text=json({packages:{'node_modules/other/node_modules/imgdecode':{version}}});}
 if(kind==='pnpm') {file='pnpm-lock.yaml';text=`packages:\n  imgdecode@${version}: {}`;}
 if(kind==='yarn') {file='yarn.lock';text=`"imgdecode@^1.0.0":\n  version "${version}"\n`;}
 if(kind==='alias') text=json({dependencies:{renamed:`npm:imgdecode@${version}`}});
 assert(has(file,text,'malfex-imgdecode-version'));
});
for(const version of ['1.0.4','11.0.3','0.1.3']) test('unlisted MALFEX version '+version,()=>{
 assert(!has('package.json',json({dependencies:{imgdecode:version}}),'malfex-imgdecode-version'));
});
test('ranges stay unresolved and unrelated names do not match',()=>{
 assert(has('package.json',json({dependencies:{imgdecode:'^1.0.3'}}),'malfex-imgdecode-review'));
 assert.deepEqual(inspectText('package.json',json({dependencies:{'safe-imgdecode':'1.0.3','@apexacc/cli-tools':'1.0.0'},description:'imgdecode 1.0.3'})),[]);
});
for(const name of ['@apexacc/cli','@apexacc/audit']) test('Apex identity is only review: '+name,()=>{
 const hits=inspectText('package.json',json({dependencies:{[name]:'1.0.0'}}));
 assert.equal(hits.length,1);assert.equal(hits[0].severity,'medium');assert.match(hits[0].message,/not pinned/);
 assert(has('pnpm-lock.yaml',`  '${name}@1.0.0': {}`,'apex-package-review'));
 assert(has('yarn.lock',`"${name}@^1.0.0":\n  version "1.0.0"`,'apex-package-review'));
});
for(const provider of ['ssh','sftp']) for(const version of ['6.0.1','7.0.0']) test(`Airflow ${provider} ${version}`,()=>{
 assert.equal(has('requirements.txt',`apache-airflow-providers-${provider}==${version}\n`,'airflow-host-key-version'),version==='6.0.1');
 assert.equal(has('uv.lock',`[[package]]\nname = "apache-airflow-providers-${provider}"\nversion = "${version}"\n`,'airflow-host-key-version'),version==='6.0.1');
 assert.equal(has('METADATA',`Name: apache-airflow-providers-${provider}\nVersion: ${version}\n`,'airflow-host-key-version'),version==='6.0.1');
});
test('Airflow constraints do not borrow neighboring versions',()=>{
 const text='apache-airflow-providers-ssh>=7.0.0\nother==6.0.1\n';
 assert(!has('requirements.txt',text,'airflow-host-key-version'));
 assert(has('requirements.txt',text,'airflow-provider-review'));
 assert(!has('requirements.txt','not-apache-airflow-providers-ssh==6.0.1','airflow-host-key-version'));
});
test('Airflow explicit controls remain separate leads',()=>{
 assert(has('dag.py','SSHHook(no_host_key_check=True)','airflow-host-key-disabled'));
 assert(has('dag.py','SFTPHookAsync(known_hosts=None)','airflow-host-key-disabled'));
 assert(has('airflow.json',json({airflow:true,extra:{no_host_key_check:false,host_key:'fixture'}}),'airflow-host-key-opt-in'));
 assert(!has('airflow.json',json({airflow:true,extra:{no_host_key_check:false}}),'airflow-host-key-disabled'));
});
const font='fa-solid-400.'+'woff2';
const task=(command,runOn='folderOpen')=>json({tasks:[{command,runOptions:{runOn}}]});
test('folder-open Node execution versus ordinary fonts',()=>{
 assert(has('tasks.json',task('node ./public/fonts/'+font),'vscode-autorun-fake-font-task'));
 assert(has('tasks.json',task('(command -v node >/dev/null 2>&1 && node ./public/fonts/'+font+')'),'vscode-autorun-fake-font-task'));
 assert(!has('tasks.json',task('cp ./public/fonts/'+font+' ./dist/'),'vscode-autorun-fake-font-task'));
 assert(!has('tasks.json',task('node ./public/fonts/'+font,'default'),'vscode-autorun-fake-font-task'));
 assert(!has('tasks.json',json({tasks:[{command:'echo ok',runOptions:{runOn:'folderOpen'}},{command:'node '+font}]}),'vscode-autorun-fake-font-task'));
});
test('collector and verification host boundaries',()=>{
 for(const host of ['my-github.com','193.32.204.199']) {
  assert(has('workflow.yml',`run: curl https://${host}/collect`,'ghostaction-collector-review'));
  assert(!has('workflow.yml',`run: curl https://${host}.example.invalid/collect`,'ghostaction-collector-review'));
 }
 assert(has('config.json','{"url":"https://vrf.apexaccs.org/api/v1/vrf"}','apex-verification-endpoint'));
 assert(!has('config.json','{"url":"https://vrf.apexaccs.org.example.invalid/api/v1/vrf"}','apex-verification-endpoint'));
});
for(const [version,affected] of [['1.6.9',false],['1.7.0',true],['2.13.5',true],['2.13.6',false],['2.14.0',true],['2.14.4',true],['2.14.5',false],['2.15.2',true],['2.15.3',false],['2.16.0',false]]) test('Harbor '+version,()=>{
 assert.equal(harborAffected(version),affected);
 assert.equal(has('compose.yml',`image: goharbor/harbor-core:v${version}\n`,'harbor-webhook-ssrf-version'),affected);
});
for(const [version,affected] of [['8.11.0',false],['8.12.0',true],['8.14.2',true],['8.14.3',false],['8.14.4',false],['8.16.1',true],['8.16.2',false],['8.20.1',true],['8.20.2',false],['8.21.0',true],['8.22.0',true],['8.23.0',false]]) test('curl '+version,()=>{
 assert.equal(curlAffected(version),affected);
 assert.equal(has('/var/lib/dpkg/status',`Package: curl\nStatus: install ok installed\nVersion: ${version}-1ubuntu1\n`,'curl-http2-package-review'),affected);
});
test('AnyDesk version inventory does not overclaim reachability',()=>{
 for(const [version,id] of [['8.0.2','anydesk-linux-version'],['8.0.1','anydesk-linux-review']])
  assert(has('/var/lib/dpkg/status',`Package: anydesk\nStatus: install ok installed\nVersion: ${version}\n`,id));
 assert.deepEqual(inspectText('/var/lib/dpkg/status','Package: anydesk\nStatus: install ok installed\nVersion: 8.0.3\n'),[]);
 assert.deepEqual(inspectText('/var/lib/dpkg/status','Package: anydesk\nStatus: deinstall ok config-files\nVersion: 8.0.2\n'),[]);
});
test('bounded reads report unreadable, malformed and symlink candidates',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'package.json');
 fs.writeFileSync(file,'not json');assert.equal(inspectFile(file)[0].type,'october-review-incomplete');
 fs.unlinkSync(file);fs.symlinkSync(path.join(root,'absent'),file);assert.equal(inspectFile(file)[0].type,'october-review-incomplete');
});
test('default scanner integration catches confirmed gaps',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const home=path.join(root,'home','fixture');fs.mkdirSync(path.join(home,'.vscode'),{recursive:true});
 fs.writeFileSync(path.join(home,'package.json'),json({dependencies:{imgdecode:'1.0.3','@apexacc/cli':'1.0.0'}}));
 fs.writeFileSync(path.join(home,'requirements.txt'),'apache-airflow-providers-ssh==6.0.1\n');
 fs.writeFileSync(path.join(home,'.vscode','tasks.json'),task('node ./public/fonts/'+font));
 const host=fs.existsSync(path.join(__dirname,'../src/checker.js'));
 const report=host?require('../src/checker').scanHost({targetRoot:root,homePath:home}):require('../src/scanner').scanTarget(home);
 const ids=report.findings.map(f=>f.id||f.type);
 for(const id of ['malfex-imgdecode-version','apex-package-review','airflow-host-key-version','vscode-autorun-fake-font-task']) assert(ids.includes(id),id);
});

test('JSONC tasks preserve strings and accept comments and trailing commas',()=>{
 const text='{"tasks":[/* fixture */{"command":"node ./public/fonts/'+font+'","runOptions":{"runOn":"folderOpen",},},],}';
 assert(has('tasks.json',text,'vscode-autorun-fake-font-task'));
 assert(!has('tasks.json','{"tasks":[{"command":"echo https://example.invalid/", "runOptions":{"runOn":"folderOpen"}}]}','vscode-autorun-fake-font-task'));
});

test('large ordinary source is outside text scope without a false risk escalation',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-scope-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'node_modules','typescript','lib','typescript.js');
 fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'// ordinary library text\n'.repeat(400000));
 const hits=inspectFile(file,{root});
 assert.equal(hits.length,1);assert.equal(hits[0].severity,'info');
 assert.equal(hits[0].type,'october-review-text-out-of-scope');
 if(fs.existsSync(path.join(__dirname,'../src/scanner.js'))) {
  const report=require('../src/scanner').scanTarget(root);
  assert.equal(report.risk,'no-known-indicators');assert.equal(report.coverage.complete,true);
  assert(report.findings.some(f=>f.type==='october-review-text-out-of-scope'));
 }
});
test('incidental malformed JSON does not masquerade as broken active configuration',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-scope-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 for(const relative of ['node_modules/tool/test/fixtures/broken/package.json','test/fixtures/tasks.json']) {
  const file=path.join(root,relative);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'{invalid');
  const hits=inspectFile(file,{root});assert.equal(hits[0].type,'october-review-incidental-json');assert.equal(hits[0].severity,'low');
 }
 if(fs.existsSync(path.join(__dirname,'../src/scanner.js'))) {
  const report=require('../src/scanner').scanTarget(root);
  assert.equal(report.coverage.complete,true);
  assert(!report.findings.some(f=>f.type==='october-review-incomplete'));
  // Tensorlake retains its separate existing malformed-manifest coverage policy.
  assert(report.findings.filter(f=>f.type.startsWith('october-review-')).every(f=>f.severity==='low'));
 }
 for(const relative of ['package.json','packages/app/package.json','node_modules/tool/package.json','node_modules/@scope/tool/package.json','.vscode/tasks.json']) {
  const file=path.join(root,relative);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'{invalid');
  assert.equal(inspectFile(file,{root})[0].type,'october-review-incomplete');
 }
});
test('incidental metadata still detects malicious versions and refuses ambiguous escapes',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-scope-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'test','fixtures','package.json');fs.mkdirSync(path.dirname(file),{recursive:true});
 fs.writeFileSync(file,json({dependencies:{imgdecode:'1.0.3'}}));
 assert(inspectFile(file,{root}).some(f=>f.type==='malfex-imgdecode-version'));
 for(const text of ['{imgdecode',String.raw`{"name":"\u0069mgdecode",invalid`]) {
  fs.writeFileSync(file,text);assert.equal(inspectFile(file,{root})[0].type,'october-review-incomplete');
 }
});
test('large lock metadata finds MALFEX beyond the former 2 MiB cutoff',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'october-large-lock-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'package-lock.json');
 fs.writeFileSync(file,json({name:'ordinary-project',description:'x'.repeat(9*1024*1024),packages:{'node_modules/imgdecode':{version:'1.0.3'}}}));
 assert(inspectFile(file,{root}).some(f=>f.type==='malfex-imgdecode-version'));
 const host=fs.existsSync(path.join(__dirname,'../src/checker.js'));
 const report=host?require('../src/checker').scanHost({targetRoot:root,homePath:root}):require('../src/scanner').scanTarget(root);
 assert(report.findings.some(f=>(f.id||f.type)==='malfex-imgdecode-version'));
 fs.writeFileSync(file,' '.repeat(32*1024*1024+1));
 assert.equal(inspectFile(file,{root})[0].type,'october-review-incomplete');
});
