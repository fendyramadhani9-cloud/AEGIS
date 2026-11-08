// AEGIS Security Monitor Service Worker
const CACHE_NAME = 'aegis-cache-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/favicon.png',
  '/brand/aegis-mark-192.png',
  '/manifest.webmanifest'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Pass-through for /api calls, cache-first for static assets
  if (event.request.url.includes('/api/')) {
    return;
  }
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      return cachedResponse || fetch(event.request);
    })
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

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  let targetUrl = '/';
  if (event.notification.data && typeof event.notification.data.url === 'string') {
    const rawUrl = event.notification.data.url.trim();
    if (rawUrl.startsWith('/') && !rawUrl.startsWith('//') && !rawUrl.includes(':')) {
      targetUrl = rawUrl;
    }
  }
  event.waitUntil(
    clients.openWindow(targetUrl)
  );
});

