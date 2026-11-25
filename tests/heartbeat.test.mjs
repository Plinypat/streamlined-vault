import {test} from 'node:test';
import assert from 'node:assert/strict';
import {heartbeat} from '../server/notifications.mjs';
const url='https://hc-ping.com/11111111-1111-1111-1111-111111111111';
test('heartbeat retries transient network failures without sending payloads',async()=>{
 let calls=0;
 const result=await heartbeat(url,'success',{retryDelay:0,fetcher:async(u,o)=>{calls++;assert.equal(u,url);assert.equal(o.body,'');assert.equal(o.redirect,'error');if(calls===1)throw Error('timeout');return {ok:true};}});
 assert.equal(calls,2);assert.equal(result.accepted,true);
});
test('heartbeat fails after bounded attempts and never retries permanent rejection',async()=>{
 let calls=0;await assert.rejects(()=>heartbeat(url,'success',{retryDelay:0,fetcher:async()=>{calls++;return {ok:false,status:503};}}),e=>e.code==='MONITOR_DELIVERY_FAILED');assert.equal(calls,2);
 calls=0;await assert.rejects(()=>heartbeat(url,'success',{retryDelay:0,fetcher:async()=>{calls++;return {ok:false,status:403};}}),e=>e.code==='MONITOR_DELIVERY_FAILED');assert.equal(calls,1);
});
