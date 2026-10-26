import {test,type TestContext} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {Store} from '../store/store.js';
import {Directory} from '../store/directory.js';
import {Ingest,type Credential} from '../ingest.js';
import {Cadence} from '../cadence.js';
import {Duty} from '../duty.js';
import {newSecret} from '../domain/auth.js';
import {parseCheckin} from '../domain/ingest.js';
const T=Date.parse('2026-10-26T12:00:00Z'),A='a'.repeat(24),B='b'.repeat(24),C='c'.repeat(24);
function fixture(t:TestContext){
  const folder=mkdtempSync(path.join(tmpdir(),'quotum-collections-')),store=new Store(path.join(folder,'db'),T);
  t.after(()=>{store.close();rmSync(folder,{recursive:true});});
  const directory=new Directory(store.db),duty=new Duty(),cadence=new Cadence(),ingest=new Ingest(store,directory,duty,cadence);
  const user=directory.createUser('fixture@example.test','Fixture','x',T),secret=newSecret('qt_m');directory.createToken(secret,'…',user.id,'test',T);
  const credential=ingest.authenticate(`Bearer ${secret}`) as Credential;
  const sender={version:1,agent:'quotum/fixture',machine:{id:'fixture-machine-01234567',name:'fixture',os:'linux',arch:'x86_64'}};
  const ask=(at:number,accounts:string[],roster?:string[])=>ingest.checkin(credential,{...sender,paced:true,capabilities:{measurementPolicy:1,attemptContext:1,accountRosters:1,collectionCompletions:1},subscriptions:accounts.map(account=>({provider:'codex',account,active:false})),...(roster?{accountRosters:[{provider:'codex',accounts:roster.map(account=>({account}))}]}:{})},T+at);
  const device=()=>directory.deviceByMachine(user.id,sender.machine.id)!;
  const context=(account:string,commandId?:string)=>({version:1,authority:store.measurementPolicies.device(device().id).authority,collectorEpoch:0,target:{kind:'verified',accountKey:account},...(commandId?{commandId}:{})});
  const deliver=(at:number,account:string,commandId?:string)=>ingest.accept(credential,{...sender,sentAt:new Date(T+at).toISOString(),snapshots:[{provider:'codex',account,observedAt:new Date(T+at).toISOString(),via:'fixture',staleAfterMs:120000,windows:[{id:'session',kind:'session',usedPercent:50}],attemptContext:context(account,commandId)}]},T+at);
  const complete=(at:number,account:string,commandId?:string)=>ingest.accept(credential,{...sender,sentAt:new Date(T+at).toISOString(),completions:[{provider:'codex',outcome:'no_new_data',completedAt:new Date(T+at).toISOString(),attemptContext:context(account,commandId)}]},T+at);
  return {store,directory,duty,cadence,ingest,user,sender,ask,device,context,deliver,complete,credential};
}
test('explicit membership survives subsets, withdraws all missing accounts and rejects late association restoration',t=>{
  const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);assert.deepEqual(answer.capabilities,{accountRosters:1,collectionCompletions:1});
  f.deliver(1000,A,answer.subscriptions[0].commandId);f.deliver(2000,B,answer.subscriptions[1].commandId);
  assert.equal(f.store.deviceSources(f.user.id).length,2);
  f.ask(3000,[B]);assert.equal(f.store.deviceSources(f.user.id).length,2);
  f.ask(4000,[B],[B]);assert.equal(f.store.deviceSources(f.user.id).length,1);
  f.deliver(5000,A,answer.subscriptions[0].commandId);assert.equal(f.store.deviceSources(f.user.id).length,1);assert.ok(f.store.findSource('codex',A));
  f.ask(6000,[],[]);assert.equal(f.store.deviceSources(f.user.id).length,0);
  assert.deepEqual([...f.store.accountRoster(f.device().id,'codex')!],[]);
});
test('account failures are independent and success clears only its own failure',t=>{
  const f=fixture(t);f.ask(0,[A,B],[A,B]);
  for(const [index,account] of [A,B].entries())f.ingest.accept(f.credential,{...f.sender,sentAt:new Date(T+1000+index).toISOString(),failures:[{provider:'codex',error:'timeout',observedAt:new Date(T+1000+index).toISOString(),attemptContext:f.context(account)}]},T+1000+index);
  assert.equal(f.store.deviceFailures(f.user.id).length,2);
  f.deliver(3000,A);assert.deepEqual(f.store.deviceFailures(f.user.id).map(f=>f.accountKey),[B]);
});
test('no-data completes its exact command and refresh once without changing resources or renewing duty',t=>{
  const f=fixture(t),first=f.ask(0,[A],[A]);f.deliver(1000,A,first.subscriptions[0].commandId);
  const source=f.store.findSource('codex',A)!,before=JSON.stringify(f.store.state(source));
  f.ingest.requestRefresh(source,T+61000);const next=f.ask(61000,[A]);assert.equal(next.subscriptions[0].measure,true);
  const until=f.duty.until(A),result=f.complete(62000,A,next.subscriptions[0].commandId);
  assert.equal(result.completions,1);assert.equal(f.ingest.refresh(source,T+62000).value.request?.status,'no_new_data');
  assert.equal(JSON.stringify(f.store.state(source)),before);assert.ok(f.duty.until(A)!<=until!);
  assert.equal(f.complete(63000,A,next.subscriptions[0].commandId).completions,0);
  assert.equal(f.ask(63000,[A]).subscriptions[0].measure,false);
  assert.equal(f.complete(64000,A,'00000000-0000-4000-8000-000000000000').completions,0);
});
test('rosters validate canonical identities and allow all 48 subscriptions',()=>{
  const sender={version:1,agent:'fixture',machine:{id:'test',name:'test',os:'linux',arch:'x'}};
  assert.throws(()=>parseCheckin({...sender,accountRosters:[{provider:'antigravity',accounts:[{}]}]}));
  assert.throws(()=>parseCheckin({...sender,accountRosters:[{provider:'codex'}]}));
  assert.throws(()=>parseCheckin({...sender,accountRosters:[{provider:'codex',accounts:[{account:A},{account:A}]}]}));
  assert.equal(parseCheckin({...sender,accountRosters:[{provider:'antigravity',accounts:[{accountName:null},{accountName:'default'}]}]}).accountRosters[0].accounts.length,2);
  assert.equal(parseCheckin({...sender,subscriptions:Array.from({length:48},()=>({provider:'codex',account:C}))}).subscriptions.length,48);
});

test('explicit roster deliveries never become inferred native session funding',t=>{
  const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);f.deliver(1000,A,answer.subscriptions[0].commandId);f.deliver(2000,B,answer.subscriptions[1].commandId);
  f.ingest.sessions(f.credential,{...f.sender,sentAt:new Date(T+3000).toISOString(),sessions:[{provider:'codex',origin:'terminal',startedAt:new Date(T).toISOString(),working:true}]},T+3000);
  const sessions=f.ingest.live.deviceSessions(f.user.id,f.device().id,T+3000);
  assert.equal(sessions.length,1);assert.equal(sessions[0].source,null);
});

test('retained refresh completion cannot answer or move the new holder command',t=>{
  const f=fixture(t),first=f.ask(0,[A],[A]);f.deliver(1000,A,first.subscriptions[0].commandId);
  const source=f.store.findSource('codex',A)!;f.ingest.requestRefresh(source,T+61000);const original=f.ask(61000,[A]).subscriptions[0];
  f.cadence.retainDispatched(A,f.device().id);f.duty.release(A,f.device().id);f.cadence.released(A,f.device().id);
  const other={...f.sender,machine:{...f.sender.machine,id:'other-fixture-machine'}};
  const answer=f.ingest.checkin(f.credential,{...other,paced:true,capabilities:{measurementPolicy:1,attemptContext:1},subscriptions:[{provider:'codex',account:A,active:true}]},T+62000).subscriptions[0];
  assert.equal(answer.measure,true);const second=f.directory.deviceByMachine(f.user.id,other.machine.id)!;
  const lease=f.duty.until(A);assert.ok(f.cadence.awaiting(A,second.id));
  const result=f.complete(63000,A,original.commandId);assert.equal(result.completions,1);
  assert.equal(f.ingest.refresh(source,T+63000).value.request?.status,'no_new_data');
  assert.equal(f.duty.until(A),lease);assert.ok(f.cadence.awaiting(A,second.id));
  assert.equal(f.complete(64000,A,original.commandId).completions,0);
});

test('completion retries and duplicates count one effective item',t=>{
  const f=fixture(t),answer=f.ask(0,[A],[A]);
  const item={provider:'codex',outcome:'no_new_data',completedAt:new Date(T+1000).toISOString(),attemptContext:f.context(A,answer.subscriptions[0].commandId)};
  const result=f.ingest.accept(f.credential,{...f.sender,sentAt:new Date(T+1000).toISOString(),completions:[item,item]},T+1000);
  assert.equal(result.completions,1);assert.equal(result.duplicates,1);assert.equal(f.complete(2000,A,answer.subscriptions[0].commandId).completions,0);
});

test('withdrawn verified failures cannot become unknown errors on a healthy sibling',t=>{
  const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);f.deliver(1000,A,answer.subscriptions[0].commandId);f.deliver(2000,B,answer.subscriptions[1].commandId);
  const b=f.store.findSource('codex',B)!,before=JSON.stringify(f.store.state(b));f.ask(3000,[B],[B]);
  f.ingest.accept(f.credential,{...f.sender,sentAt:new Date(T+4000).toISOString(),failures:[{provider:'codex',error:'timeout',observedAt:new Date(T+4000).toISOString(),attemptContext:f.context(A,answer.subscriptions[0].commandId)}]},T+4000);
  assert.deepEqual(f.store.deviceFailures(f.user.id),[]);assert.equal(JSON.stringify(f.store.state(b)),before);
});

test('a roster member keeps independent evidence when its observation arrives behind another account',t=>{
  const f=fixture(t);f.ask(0,[A,B],[A,B]);f.deliver(5000,A);f.deliver(3000,B);
  const keys=f.ingest.measurementSelection.candidateAccounts(f.device().id).map(account=>account.key);
  assert.ok(keys.includes(A));assert.ok(keys.includes(B));assert.equal(f.store.deviceSources(f.user.id).length,2);
});

test('revocation releases orphan holdings before removing every account association',t=>{
  const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);f.deliver(1000,A,answer.subscriptions[0].commandId);f.deliver(2000,B,answer.subscriptions[1].commandId);
  f.directory.transaction(()=>{f.directory.revokeDevice(f.user.id,f.device().id,T+3000);f.store.releaseRevoked(f.user.id);});
  assert.equal(f.store.deviceSources(f.user.id).length,0);assert.equal(f.store.held(f.user.id).length,0);
});

test('no-data waiting never renews an expired starter and another healthy device can take duty',t=>{
  const f=fixture(t);
  const body={...f.sender,paced:true,capabilities:{measurementPolicy:1,attemptContext:1},subscriptions:[{provider:'codex',account:A,active:false,minIntervalMs:600000}]};
  const first=f.ingest.checkin(f.credential,body,T).subscriptions[0];
  assert.equal(first.measure,true);assert.equal(f.duty.until(A),T+300000);
  assert.equal(f.complete(1000,A,first.commandId).completions,1);
  assert.equal(f.ingest.checkin(f.credential,body,T+301000).subscriptions[0].measure,false);
  assert.equal(f.duty.until(A),T+300000,'waiting A has no fresh starter lease');
  const other={...body,machine:{...f.sender.machine,id:'healthy-fixture-machine'}};
  const takeover=f.ingest.checkin(f.credential,other,T+302000).subscriptions[0];
  assert.equal(takeover.measure,true);
  assert.equal(f.duty.holder(A),f.directory.deviceByMachine(f.user.id,other.machine.id)!.id);
  assert.equal(f.duty.until(A),T+602000,'only an actual command protects B');
});

test('withdrawn provenance releases every orphan holding, including a first late observation',t=>{
  for(const firstLate of [false,true]){
    const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);
    if(!firstLate)f.deliver(1000,A,answer.subscriptions[0].commandId);
    f.deliver(2000,B,answer.subscriptions[1].commandId);f.ask(3000,[B],[B]);
    f.ingest.accept(f.credential,{...f.sender,sentAt:new Date(T+3500).toISOString(),failures:[{provider:'codex',error:'timeout',observedAt:new Date(T+3500).toISOString(),attemptContext:f.context(B)}]},T+3500);
    const beforeB=f.store.deviceFailures(f.user.id);
    f.deliver(4000,A,answer.subscriptions[0].commandId);
    const source=f.store.findSource('codex',A)!;
    assert.ok(f.store.holds(f.user.id,source));
    assert.ok(f.store.db.prepare('SELECT 1 FROM device_sources WHERE device_id=? AND source_id=?').get(f.device().id,source));
    assert.deepEqual(f.store.deviceSources(f.user.id).map(row=>row.source),[f.store.findSource('codex',B)]);
    assert.equal(f.store.deviceSource(f.device().id,'codex'),f.store.findSource('codex',B));
    assert.ok(!f.ingest.measurementSelection.candidateAccounts(f.device().id).some(account=>account.key===A));
    assert.deepEqual(f.store.deviceFailures(f.user.id),beforeB,'late A does not clear B diagnostics');
    const history=JSON.stringify(f.store.state(source));
    f.directory.transaction(()=>{f.directory.revokeDevice(f.user.id,f.device().id,T+5000);f.store.releaseRevoked(f.user.id);});
    assert.equal(f.store.held(f.user.id).length,0);
    assert.equal(JSON.stringify(f.store.state(source)),history,'revocation preserves source evidence');
  }
});

test('persisted membership changes invalidate owner connections after restart and identical groups are no-ops',t=>{
  const f=fixture(t),answer=f.ask(0,[A,B],[A,B]);f.deliver(1000,A,answer.subscriptions[0].commandId);f.deliver(2000,B,answer.subscriptions[1].commandId);
  const filename=f.store.db.prepare('PRAGMA database_list').get()!.file as string;
  const store=new Store(filename,T+3000);t.after(()=>store.close());
  const directory=new Directory(store.db),ingest=new Ingest(store,directory,new Duty(),new Cadence());
  const touched:string[]=[];
  store.setObserver({touchUser:user=>touched.push(user),touchSources(){},touchBoards(){},touchHub(){},history(){},dropSessions(){},dropMember(){},dropBoard(){}});
  const before=directory.connectionsRevision(f.user.id);
  const body={...f.sender,capabilities:{measurementPolicy:1,attemptContext:1,accountRosters:1},accountRosters:[{provider:'codex',accounts:[]}]};
  ingest.checkin(f.credential,body,T+3000);
  assert.equal(store.deviceSources(f.user.id).length,0);assert.ok(directory.connectionsRevision(f.user.id)>before);
  assert.ok(touched.includes(f.user.id));const revision=directory.connectionsRevision(f.user.id);touched.length=0;
  ingest.checkin(f.credential,body,T+4000);
  assert.equal(directory.connectionsRevision(f.user.id),revision);assert.deepEqual(touched,[]);
  assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM device_sources WHERE device_id=?').get(f.device().id)!.n,2,'raw provenance remains');
});

test('native current-source inference uses only its latest association while retaining older provenance',t=>{
  const f=fixture(t);f.ask(0,[A]);f.deliver(1000,A);f.ask(2000,[B]);f.deliver(3000,B);
  assert.deepEqual(f.store.deviceSources(f.user.id).map(row=>row.source),[f.store.findSource('codex',B)]);
  assert.equal(f.store.deviceSource(f.device().id,'codex'),f.store.findSource('codex',B));
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM device_sources WHERE device_id=?').get(f.device().id)!.n,2);
  f.directory.transaction(()=>{f.directory.revokeDevice(f.user.id,f.device().id,T+4000);f.store.releaseRevoked(f.user.id);});
  assert.equal(f.store.held(f.user.id).length,0);
});
