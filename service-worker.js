/* Ludo Baji Service Worker - PWA Install + Push */
const CACHE_NAME = 'ludo-baji-v5';
const PRECACHE = ['/', '/index.html', '/admin', '/admin.html', '/manifest.webmanifest', '/admin-manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/7543.jpg', '/logo-ludo-baji.jpg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE).catch(() => {})).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req).catch(() => caches.match(req)));
    return;
  }
  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req).then((res) => {
      const copy = res.clone();
      caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
      return res;
    }).catch(() => cached))
  );
});

self.addEventListener('push', (event) => {
  let data = { title: 'Ludo Baji', message: 'নতুন notification', data: {} };
  try {
    data = event.data ? event.data.json() : data;
  } catch (e) {}
  event.waitUntil(
    self.registration.showNotification(data.title || 'Ludo Baji', {
      body: data.message || '',
      icon: '/7543.jpg',
      badge: '/7543.jpg',
      data: data.data || {},
      tag: 'ludo-baji'
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) => {
      for (const c of cs) {
        if ('focus' in c) return c.focus();
      }
      return clients.openWindow('/');
    })
  );
});
