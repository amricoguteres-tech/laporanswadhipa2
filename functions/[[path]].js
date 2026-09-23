export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!url.pathname.startsWith('/api/')) {
    return next();
  }

  const backendBase = env.API_PROXY_URL || 'http://127.0.0.1:8000';
  const target = new URL(url.pathname + url.search, backendBase);

  const headers = new Headers(request.headers);
  headers.set('Host', target.host);
  headers.delete('Content-Length');

  const init = {
    method: request.method,
    headers,
    redirect: 'manual',
  };

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = await request.arrayBuffer();
  }

  const backendResponse = await fetch(target, init);

  const responseHeaders = new Headers(backendResponse.headers);
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: responseHeaders,
    });
  }

  return new Response(backendResponse.body, {
    status: backendResponse.status,
    statusText: backendResponse.statusText,
    headers: responseHeaders,
  });
}
