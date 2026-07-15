const BASE = '';

async function request(url, options = {}) {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export function fetchStats() {
  return request('/api/stats/overview');
}

export function fetchDevices() {
  return request('/api/devices');
}

export function fetchTopTalkers() {
  return request('/api/traffic/top-talkers');
}

export function fetchTopDestinations() {
  return request('/api/traffic/top-destinations');
}

export function fetchDnsQueries(limit = 50) {
  return request(`/api/dns/queries?limit=${limit}`);
}

export function fetchTopDomains() {
  return request('/api/dns/top-domains');
}

export function fetchTlsSessions() {
  return request('/api/tls/sessions');
}

export function fetchAlerts(limit = 50, severity) {
  const params = new URLSearchParams({ limit });
  if (severity) params.set('severity', severity);
  return request(`/api/alerts?${params}`);
}

export function fetchBandwidthHistory(minutes = 60) {
  return request(`/api/stats/bandwidth?minutes=${minutes}`);
}

export function fetchProtocolDistribution() {
  return request('/api/stats/protocols');
}

export function fetchFlows() {
  return request('/api/traffic/flows');
}

export function startCapture(iface) {
  return request(`/api/capture/start?interface=${encodeURIComponent(iface)}`, { method: 'POST' });
}

export function stopCapture() {
  return request('/api/capture/stop', { method: 'POST' });
}

export function fetchCaptureStatus() {
  return request('/api/capture/status');
}

export function fetchInterfaces() {
  return request('/api/capture/interfaces');
}
