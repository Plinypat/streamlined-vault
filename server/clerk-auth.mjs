import { createClerkClient } from '@clerk/backend';

const fail=(status,message,code)=>Object.assign(Error(message),{status,code});

export function clerkConfiguration(env) {
  const key=env.CLERK_PUBLISHABLE_KEY||env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY||'';
  if(!/^pk_(test|live)_[A-Za-z0-9+/=_-]+$/.test(key))throw Error('Configure CLERK_PUBLISHABLE_KEY on the server');
  const decoded=Buffer.from(key.replace(/^pk_(test|live)_/,''),'base64').toString('utf8');
  if(!decoded.endsWith('$'))throw Error('Invalid Clerk publishable key');
  const host=decoded.slice(0,-1);
  if(!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)||!host.includes('.')||host.includes('..'))throw Error('Invalid Clerk Frontend API host');
  if(!env.CLERK_SECRET_KEY)throw Error('Configure CLERK_SECRET_KEY only on the server');
  if(env.NODE_ENV==='production'&&(!key.startsWith('pk_live_')||!env.CLERK_SECRET_KEY.startsWith('sk_live_')))throw Error('Production requires Clerk live instance keys');
  const maxAge=Number(env.CLERK_MFA_MAX_AGE_MINUTES||15);
  if(!Number.isInteger(maxAge)||maxAge<5||maxAge>60)throw Error('CLERK_MFA_MAX_AGE_MINUTES must be between 5 and 60');
  return {publishableKey:key,frontendApi:'https://'+host,issuer:'https://'+host,maxAge};
}

// Verified Clerk subject -> application-owned membership. Clerk user metadata is not authorization.
export function createClerkAuth({env,origin,resolveIdentity,client}) {
  const config=clerkConfiguration(env);
  const sdk=client||createClerkClient({publishableKey:config.publishableKey,secretKey:env.CLERK_SECRET_KEY,telemetry:{disabled:true}});
  async function authenticate(req) {
    const headers=new Headers();for(const [k,v] of Object.entries(req.headers||{}))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(','):v);
    let state;
    try { state=await sdk.authenticateRequest(new Request(new URL(req.url,origin),{method:req.method,headers}),{
      acceptsToken:'session_token',authorizedParties:[origin],issuer:config.issuer,
      ...(env.CLERK_JWT_KEY?{jwtKey:env.CLERK_JWT_KEY}:{})
    }); } catch { throw fail(401,'Please sign in','SIGN_IN_REQUIRED'); }
    if(!state.isAuthenticated)throw fail(401,'Please sign in','SIGN_IN_REQUIRED');
    const auth=state.toAuth(),claims=auth.sessionClaims;
    if(!auth.userId||!auth.sessionId||claims?.sub!==auth.userId||claims?.sid!==auth.sessionId||claims?.iss!==config.issuer||claims?.azp!==origin||claims?.sts==='pending')throw fail(401,'Complete your sign-in before accessing the workspace','SIGN_IN_REQUIRED');
    const fva=claims.fva;
    if(!Array.isArray(fva)||fva.length!==2||!fva.every(n=>Number.isInteger(n)&&n>=0)||fva[1]>config.maxAge)throw fail(403,'Complete a recent MFA sign-in to access this workspace','MFA_REQUIRED');
    // Pilot deliberately checks active/revoked status online on every request, not just JWT expiry.
    const active=await sdk.sessions.getSession(auth.sessionId);
    if(active.status!=='active'||active.userId!==auth.userId)throw fail(401,'This session is no longer active','SIGN_IN_REQUIRED');
    const account=await sdk.users.getUser(auth.userId);
    const primary=account.emailAddresses?.find(e=>e.id===account.primaryEmailAddressId);
    if(account.banned||account.locked||primary?.verification?.status!=='verified')throw fail(403,'A verified, active account is required','ACCOUNT_NOT_VERIFIED');
    const email=String(primary.emailAddress).toLowerCase();
    const identity=await resolveIdentity({clerkId:auth.userId,email});
    return {...identity,email,name:[account.firstName,account.lastName].filter(Boolean).join(' ')||email,clerkId:auth.userId,clerkSessionId:auth.sessionId};
  }
  return {config,authenticate,revoke:sessionId=>sdk.sessions.revokeSession(sessionId)};
}

export function contentSecurityPolicy(frontendApi) {
  const sources=frontendApi?`${frontendApi} https://challenges.cloudflare.com https://*.protect.clerk.com`:'';
  return `default-src 'self'; script-src 'self' ${sources}; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https://img.clerk.com; connect-src 'self' ${frontendApi||''} https://challenges.cloudflare.com https://*.protect.clerk.com:*; worker-src 'self' blob:; frame-src ${sources||"'none'"}; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`;
}
