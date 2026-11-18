// Loaded only when the server explicitly configures real Clerk authentication.
let client;
function loadScript(src,key){return new Promise((resolve,reject)=>{const s=document.createElement('script');s.src=src;s.async=true;s.crossOrigin='anonymous';if(key)s.dataset.clerkPublishableKey=key;s.onload=resolve;s.onerror=()=>reject(Error('Secure sign-in could not load. Please try again.'));document.head.appendChild(s);});}
export async function initialize(config){
  if(client)return client;
  const decoded=atob(config.publishableKey.replace(/^pk_(test|live)_/,''));
  if(!decoded.endsWith('$')||config.frontendApi!==`https://${decoded.slice(0,-1)}`)throw Error('Sign-in configuration is invalid');
  await loadScript(config.frontendApi+'/npm/@clerk/ui@1/dist/ui.browser.js');
  await loadScript(config.frontendApi+'/npm/@clerk/clerk-js@6/dist/clerk.browser.js',config.publishableKey);
  if(!window.Clerk)throw Error('Secure sign-in is unavailable');
  await window.Clerk.load({ui:{ClerkUI:window.__internal_ClerkUICtor},telemetry:{disabled:true}});
  client=window.Clerk;return client;
}
export async function token(){return client?.session?await client.session.getToken():null;}
export function signedIn(){return client?.session?.status==='active';}
export function mountSignIn(element){client.mountSignIn(element,{routing:'hash',forceRedirectUrl:location.origin+'/',appearance:{variables:{colorPrimary:'#247c67',fontFamily:'Segoe UI, Arial, sans-serif',borderRadius:'0.5rem'}}});}
export async function signOut(){if(client)await client.signOut({redirectUrl:location.origin+'/'});}
export function openSecurity(){client?.openUserProfile();}
