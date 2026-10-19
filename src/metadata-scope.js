"use strict";
const path = require("path");
function incidentalJson(file,root) {
 if(!root) return false;
 const rel=path.relative(root,file).split(path.sep);
 const base=path.basename(file);
 if(base==='tasks.json') return rel.at(-2)!=='.vscode';
 if(base!=='package.json') return false;
 if(rel.length===1) return false;
 const last=rel.lastIndexOf('node_modules');
 if(last>=0) {
  const tail=rel.slice(last+1);
  return !(tail.length===2 || (tail.length===3 && tail[0].startsWith('@')));
 }
 // Project manifests remain required; only explicit test/example/generated trees
 // are incidental. Valid metadata in these paths is still inspected normally.
 return rel.slice(0,-1).some(x=>/^(?:tests?|__tests__|fixtures?|__fixtures__|examples?|dist|build|coverage)$/.test(x));
}
module.exports = {incidentalJson};
