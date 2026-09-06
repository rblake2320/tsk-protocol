import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const [output, modulePath, mode] = process.argv.slice(2);
const { FileTumblerStore } = await import(pathToFileURL(resolve(modulePath)).href);
if(mode==='child') {
  try {
    const store=new FileTumblerStore(output,{maxAgeSec:0});
    const result=await store.commitValidation('synthetic',{counterMatches:[{segmentId:'counter',matchedCounter:7}],usedAt:Date.now()});
    console.log(JSON.stringify({accepted:result.ok,error:result.error}));
  } catch(error) {
    assert.match(error.message,/TSK_FILE_STORE_LOCK_UNAVAILABLE/);
    console.log(JSON.stringify({accepted:false,lockUnavailable:true}));
  }
} else {
  const out=resolve(output);mkdirSync(out);
  const receipt={ok:false,cases:[]};
  const map={clientId:'synthetic',sharedSecret:'00'.repeat(32),keyLength:20,
    segments:[{segmentId:'counter',type:'hotp',position:[0,10],counter:7}],
    checksum:{position:[10,20]},createdAt:Date.now(),version:'1'};
  const input={counterMatches:[{segmentId:'counter',matchedCounter:7}],usedAt:Date.now()};
  const check=(name,condition)=>{assert(condition,name);receipt.cases.push({name,ok:true});};
  try {
    const file=resolve(out,'two-instances.json');
    const a=new FileTumblerStore(file,{maxAgeSec:0});await a.set('synthetic',map);
    for(const id of ['__proto__','constructor','prototype','']) {
      await assert.rejects(a.get(id),/CLIENT_ID_INVALID/);
      await assert.rejects(a.set(id,{...map,clientId:id}),/CLIENT_ID_INVALID/);
      check('reserved/empty identity rejected: '+id,true);
    }
    const b=new FileTumblerStore(file,{maxAgeSec:0});
    const one=await a.commitValidation('synthetic',input);const two=await b.commitValidation('synthetic',input);
    check('two instances cannot both consume same counter',one.ok && !two.ok);
    check('persisted count equals one accepted validation',(await b.get('synthetic')).requestCount===1);
    const concurrent=resolve(out,'two-processes.json');await new FileTumblerStore(concurrent,{maxAgeSec:0}).set('synthetic',map);
    function child(){return new Promise((res,rej)=>{
      const p=spawn(process.execPath,[fileURLToPath(import.meta.url),concurrent,resolve(modulePath),'child'],{windowsHide:true});
      let stdout='',stderr='';p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('error',rej);
      p.on('exit',code=>code===0?res(JSON.parse(stdout)):rej(Error(stderr)));
    });}
    const children=await Promise.all([child(),child()]);receipt.children=children;
    check('two processes produce exactly one acceptance',children.filter(x=>x.accepted).length===1);
    check('two-process persisted count is one',(await new FileTumblerStore(concurrent,{maxAgeSec:0}).get('synthetic')).requestCount===1);
    const invalid=[['missing-created',m=>delete m.createdAt],['string-created',m=>m.createdAt='0'],
      ['negative-counter',m=>m.segments[0].counter=-1],['missing-counter',m=>delete m.segments[0].counter],
      ['invalid-status',m=>m.status='anything'],['identity-mismatch',m=>m.clientId='other'],['overlapping-segment',m=>m.segments[0].position=[1,10]]];
    for(const [name,mutate] of invalid){
      const bad=structuredClone(map);mutate(bad);const path=resolve(out,name+'.json');
      const raw=JSON.stringify({maps:{synthetic:bad},lastAccess:{synthetic:Date.now()}});writeFileSync(path,raw);
      assert.throws(()=>new FileTumblerStore(path),/TSK_FILE_STORE_CORRUPT/);
      check(name+' rejected without altering file',readFileSync(path,'utf8')===raw);
    }
    for(const [name,cfg] of [['nan-age',{maxAgeSec:NaN}],['infinite-age',{maxAgeSec:Infinity}],['zero-capacity',{maxEntries:0}]]) {
      assert.throws(()=>new FileTumblerStore(resolve(out,name+'.json'),cfg),/CONFIG_INVALID/);check(name+' rejected',true);
    }
    const expired=resolve(out,'expired.json');const expiry=new FileTumblerStore(expired,{maxAgeSec:1});
    await expiry.set('synthetic',{...map,createdAt:Date.now()-5000});
    check('direct commit rechecks TTL',!(await expiry.commitValidation('synthetic',input)).ok);
    check('expired map never returned',(await expiry.get('synthetic'))===null);
    const locked=resolve(out,'retained-lock.json');const ls=new FileTumblerStore(locked,{maxAgeSec:0});await ls.set('synthetic',map);
    writeFileSync(locked+'.lock','{"owner":"retained-test-intent"}');
    assert.throws(()=>ls.commitValidation('synthetic',input),/LOCK_UNAVAILABLE/);
    check('retained lock refuses operation without breaking ownership',JSON.parse(readFileSync(locked,'utf8')).maps.synthetic.segments[0].counter===7);
    receipt.ok=true;
  } finally {writeFileSync(resolve(out,'receipt.json'),JSON.stringify(receipt,null,2));}
  console.log(JSON.stringify(receipt));
}
