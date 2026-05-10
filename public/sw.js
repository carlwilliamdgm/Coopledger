const CACHE_NAME = 'coopledger-v2';
const APP_SHELL = [
  '/',
  '/js/app.js',
  '/manifest.json',
  '/css/style.css',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('push', (event) => {
  let title = 'CoopLedger';
  let body = '';
  let data = { url: '/' };

  try {
    if (event.data) {
      const parsed = event.data.json();
      title = parsed.title || title;
      body = parsed.body || body;
      data = parsed.data || data;
    }
  } catch (_) {
    body = event.data ? String(event.data.text()) : '';
  }

  const targetUrl = data.url || '/';

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      data: { url: targetUrl },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const urlPath = (event.notification.data && event.notification.data.url) || '/';
  const fullUrl = new URL(urlPath, self.location.origin).href;

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (clients) => {
      for (const client of clients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          await client.focus();
          return;
        }
      }
      await self.clients.openWindow(fullUrl);
    })
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  if (url.origin !== self.location.origin) {
    return;
  }

  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstApi(request));
    return;
  }

  if (request.method === 'GET') {
    event.respondWith(cacheFirstWithBackgroundUpdate(request));
  }
});

async function cacheFirstWithBackgroundUpdate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cachedResponse = await cache.match(request);

  const updateCache = fetch(request)
    .then(response => {
      if (response.ok) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => null);

  return cachedResponse || updateCache || fetch(request);
}

async function networkFirstApi(request) {
  const cache = await caches.open(CACHE_NAME);

  try {
    const response = await fetch(request);

    if (request.method === 'GET' && response.ok) {
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    if (request.method === 'GET') {
      const cachedResponse = await cache.match(request);
      if (cachedResponse) {
        return cachedResponse;
      }
    }

    return new Response(JSON.stringify({ offline: true }), {
      status: 503,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }
}
