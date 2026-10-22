const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('vk_mcp/web/vk-access-check.js', 'utf8');

function fixture({standalone=false,rejectSearch=false}={}) {
  const elements = new Map();
  for (const id of ['probe','status','authorize','copy','results']) {
    elements.set(id,{dataset:{appId:'54845887'},disabled:true,textContent:'',events:{},
      addEventListener(name,fn){this.events[name]=fn;},replaceChildren(){},appendChild(){}});
  }
  const calls=[];
  const copies=[];
  const win={parent:{},addEventListener(){},vkBridge:{async send(method,args){
    calls.push({method,args});
    if (method==='VKWebAppInit') return {};
    if (method==='VKWebAppGetAuthToken') return {access_token:'FAKE_TEST_TOKEN',scope:'groups'};
    if (rejectSearch) throw {error_data:{error_code:15}};
    return {response:{count:1,items:[{name:'Example'}]}};
  }}};
  if (standalone) win.parent=win;
  const context={window:win,document:{getElementById:id=>elements.get(id),createElement:()=>({textContent:''})},
    navigator:{clipboard:{async writeText(value){copies.push(value);}}}};
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
