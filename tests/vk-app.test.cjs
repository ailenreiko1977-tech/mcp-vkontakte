const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('vk_mcp/web/vk-access-check.js', 'utf8');

function fixture({standalone=false,rejectSearch=false,rejectClipboard=false,rejectBridgeCopy=false}={}) {
  const elements = new Map();
  for (const id of ['probe','status','authorize','copy','results','show-key','manual','manual-key']) {
    elements.set(id,{dataset:{appId:'54845887'},disabled:true,hidden:true,textContent:'',value:'',events:{},
      addEventListener(name,fn){this.events[name]=fn;},replaceChildren(){},appendChild(){},focus(){},select(){this.selected=true;}});
  }
  const calls=[];
  const copies=[];
  const win={parent:{},addEventListener(){},vkBridge:{async send(method,args){
    calls.push({method,args});
    if (method==='VKWebAppInit') return {};
    if (method==='VKWebAppGetAuthToken') return {access_token:'FAKE_TEST_TOKEN',scope:'groups'};
    if (method==='VKWebAppCopyText') {
      if (rejectBridgeCopy) throw new Error('Clipboard disabled');
      copies.push(args.text); return {result:true};
    }
    if (rejectSearch) throw {error_data:{error_code:15}};
    return {response:{count:1,items:[{name:'Example'}]}};
  }}};
  if (standalone) win.parent=win;
  const context={window:win,document:{getElementById:id=>elements.get(id),createElement:()=>({textContent:''})},
    navigator:{clipboard:{async writeText(value){if(rejectClipboard) throw new Error('Clipboard blocked'); copies.push(value);}}}};
  vm.runInNewContext(source,context);
  return {elements,calls,copies};
}

test('standalone page never requests a token',async()=>{
  const f=fixture({standalone:true});
  await new Promise(setImmediate);
  assert.equal(f.elements.get('authorize').disabled,true);
  assert.equal(f.calls.length,0);
});
test('consent click requests only groups and copy requires a passed search',async()=>{
  const f=fixture(); await new Promise(setImmediate);
  assert.deepEqual(f.calls.map(c=>c.method),['VKWebAppInit']);
  await f.elements.get('authorize').events.click();
  const auth=f.calls.find(c=>c.method==='VKWebAppGetAuthToken');
  assert.equal(auth.args.scope,'groups');
  assert.equal(auth.args.app_id,54845887);
  assert.equal(f.calls.find(c=>c.method==='VKWebAppCallAPIMethod').args.method,'groups.search');
  assert.equal(f.elements.get('copy').disabled,false);
  assert.equal(f.copies.length,0);
  assert.ok(![...f.elements.values()].some(e=>e.textContent.includes('FAKE_TEST_TOKEN')));
  await f.elements.get('copy').events.click();
  assert.deepEqual(f.copies,['FAKE_TEST_TOKEN']);
});
test('VK refusal does not offer a useless token for storage',async()=>{
  const f=fixture({rejectSearch:true}); await new Promise(setImmediate);
  await f.elements.get('authorize').events.click();
  assert.equal(f.elements.get('copy').disabled,true);
  await f.elements.get('copy').events.click();
  assert.equal(f.copies.length,0);
  assert.ok(f.elements.get('status').textContent.includes('15'));
});
test('iframe clipboard refusal falls back to official VK copy',async()=>{
  const f=fixture({rejectClipboard:true}); await new Promise(setImmediate);
  await f.elements.get('authorize').events.click();
  await f.elements.get('copy').events.click();
  assert.deepEqual(f.copies,['FAKE_TEST_TOKEN']);
  assert.equal(f.elements.get('manual-key').value,'');
  assert.equal(f.elements.get('manual').hidden,true);
});
test('manual display requires a separate click after both copy methods refuse',async()=>{
  const f=fixture({rejectClipboard:true,rejectBridgeCopy:true}); await new Promise(setImmediate);
  await f.elements.get('authorize').events.click();
  await f.elements.get('copy').events.click();
  assert.equal(f.elements.get('show-key').hidden,false);
  assert.equal(f.elements.get('manual').hidden,true);
  assert.equal(f.elements.get('manual-key').value,'');
  assert.equal(f.copies.length,0);
  await f.elements.get('show-key').events.click();
  assert.equal(f.elements.get('manual-key').value,'FAKE_TEST_TOKEN');
  assert.equal(f.elements.get('manual').hidden,false);
  assert.equal(f.elements.get('manual-key').selected,true);
  await f.elements.get('authorize').events.click();
  assert.equal(f.elements.get('manual-key').value,'');
  assert.equal(f.elements.get('manual').hidden,true);
});
