import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const [output,modulePath]=process.argv.slice(2);
const out=resolve(output);mkdirSync(out);
const {FileTumblerStore}=await import(pathToFileURL(resolve(modulePath)).href);
const file=resolve(out,'authority.json');
const map={clientId:'synthetic',sharedSecret:'00'.repeat(32),keyLength:20,
  segments:[{segmentId:'counter',type:'hotp',position:[0,10],counter:7}],
  checksum:{position:[10,20]},createdAt:Date.now(),version:'1'};
const store=new FileTumblerStore(file,{maxEntries:1,maxAgeSec:0});
await store.set('synthetic',map);
const before=readFileSync(file);const receipt={ok:false,cases:[]};
try {
  for(const id of Object.getOwnPropertyNames(Object.prototype)) {
    if(['__proto__','constructor'].includes(id)) {
      await assert.rejects(store.get(id),/CLIENT_ID_INVALID/);
    } else {
      assert.equal(await store.get(id),null);
      await assert.rejects(store.set(id,{...map,clientId:id}),/CAPACITY_REACHED/);
      assert.deepEqual(await store.list(),['synthetic']);
      assert.deepEqual(readFileSync(file),before);
    }
    receipt.cases.push({id,absentAndCapacityGuarded:true});
  }
  assert.equal((await store.get('synthetic')).segments[0].counter,7);
  const unusual=new FileTumblerStore(resolve(out,'unusual.json'),{maxEntries:1,maxAgeSec:0});
  await unusual.set('toString',{...map,clientId:'toString'});
  assert.equal((await unusual.get('toString')).clientId,'toString');
  assert.equal(unusual.trackedClients,1);
  receipt.unusualOwnKeyWorks=true;receipt.ok=true;
} finally {writeFileSync(resolve(out,'receipt.json'),JSON.stringify(receipt,null,2));}
console.log(JSON.stringify(receipt));
