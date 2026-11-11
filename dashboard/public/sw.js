// AEGIS Defensive Operations Service Worker
// Automatically clears stale cache on update to prevent bundle mismatch
const CACHE_NAME = 'aegis-cache-v2';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(keys.map((key) => caches.delete(key)));
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Always fetch fresh network for HTML navigations and /api calls
  if (event.request.mode === 'navigate' || event.request.url.includes('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Network-first with cache fallback for other assets
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

// Web Push Alert Notification Listener
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'AEGIS Security Alert', message: event.data ? event.data.text() : '' };
  }
  const title = data.title || 'AEGIS Security Alert';
  const options = {
    body: data.message || 'Suspicious operational activity detected.',
    icon: '/brand/aegis-mark-192.png',
    badge: '/brand/aegis-mark-192.png',
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/'
    }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});
