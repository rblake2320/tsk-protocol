import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, renameSync, rmdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [output, modulePath, mode] = process.argv.slice(2);
assert(output && modulePath && ['baseline', 'regression'].includes(mode));
const out = resolve(output); mkdirSync(out);
const { FileTumblerStore } = await import(pathToFileURL(resolve(modulePath)).href);
const file = resolve(out, 'state.json');
const store = new FileTumblerStore(file, {maxAgeSec: 0});
const map = {clientId: 'synthetic', sharedSecret: '00'.repeat(32), keyLength: 20,
  segments: [{segmentId:'counter', type:'hotp', position:[0, 10], counter:7}],
  checksum:{position:[10,20]}, createdAt:Date.now(), version:'1'};
await store.set('synthetic', map);
const before = readFileSync(file);
renameSync(file, file+'.retained'); mkdirSync(file);
let failure = '';
try { await store.commitValidation('synthetic', {counterMatches:[{segmentId:'counter',matchedCounter:7}], usedAt:Date.now()}); }
catch(error) { failure = (error as NodeJS.ErrnoException).code ?? (error as Error).name; }
assert(failure, 'real target-directory rename must fail');
const live = await store.get('synthetic');
const disk = JSON.parse(readFileSync(file+'.retained','utf8')).maps.synthetic;
const receipt:any = {mode, failure, liveCounter:live.segments[0].counter, diskCounter:disk.segments[0].counter,
  liveRequestCount:live.requestCount??0, diskRequestCount:disk.requestCount??0};
try {
  if(mode==='baseline') assert.notEqual(receipt.liveCounter,receipt.diskCounter);
  else { assert.equal(receipt.liveCounter,7); assert.equal(receipt.liveRequestCount,0); }
  rmdirSync(file); renameSync(file+'.retained',file);
  assert.deepEqual(readFileSync(file),before);
  if(mode==='regression') {
    const result = await store.commitValidation('synthetic',{counterMatches:[{segmentId:'counter',matchedCounter:7}],usedAt:Date.now()});
    assert(result.ok); const reopened = new FileTumblerStore(file,{maxAgeSec:0});
    const restored = await reopened.get('synthetic');
    assert.equal(restored.segments[0].counter,8);assert.equal(restored.requestCount,1);
    receipt.reopenedCounter=8;receipt.reopenedRequestCount=1;
    receipt.mutationCases=[];
    for(const operation of ['set','delete','updateCounters','consumeCounter','replaceCredential']) {
      const target=resolve(out,operation+'.json');
      const subject=new FileTumblerStore(target,{maxAgeSec:0});
      await subject.set('synthetic',map);
      const unchanged=JSON.stringify(await subject.get('synthetic'));
      renameSync(target,target+'.retained');mkdirSync(target);
      let denied=false;
      try {
        if(operation==='set') await subject.set('second',{...map,clientId:'second'});
        if(operation==='delete') await subject.delete('synthetic');
        if(operation==='updateCounters') await subject.updateCounters('synthetic',new Map([['counter',99]]));
        if(operation==='consumeCounter') await subject.consumeCounter('synthetic','counter',7);
        if(operation==='replaceCredential') await subject.replaceCredential('synthetic',{...map,clientId:'second'});
      } catch { denied=true; }
      assert(denied);assert.equal(JSON.stringify(await subject.get('synthetic')),unchanged);
      assert.deepEqual(await subject.list(),['synthetic']);
      rmdirSync(target);renameSync(target+'.retained',target);
      receipt.mutationCases.push({operation,failedWritePreservedAuthority:true});
    }
  }
  receipt.ok=true;
} finally { writeFileSync(resolve(out,'receipt.json'),JSON.stringify(receipt,null,2)); }
console.log(JSON.stringify(receipt));
