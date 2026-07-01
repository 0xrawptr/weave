const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1';

function buildQuery(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    query.set(key, String(value));
  });
  const text = query.toString();
  return text ? `?${text}` : '';
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.error || `${response.status} ${response.statusText}`);
  return data;
}

export const api = {
  // Auth
  login: (body) => request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),

  // Artifacts
  listArtifacts: () => request('/artifacts'),
  getArtifact: (name) => request(`/artifacts/${encodeURIComponent(name)}`),

  // Campaigns
  listCampaigns: (params) => request(`/campaigns${buildQuery(params)}`),
  getCampaign: (id) => request(`/campaigns/${encodeURIComponent(id)}`),
  createCampaign: (payload) => request('/campaigns', { method: 'POST', body: JSON.stringify(payload) }),
  updateCampaignStatus: (id, status) => request(`/campaigns/${encodeURIComponent(id)}/status`, {
    method: 'POST', body: JSON.stringify({ status }),
  }),

  // Batches
  listBatches: (params) => request(`/batches${buildQuery(params)}`),
  startBatch: (payload) => request('/batches', { method: 'POST', body: JSON.stringify(payload) }),
  stopBatch: (id) => request(`/batches/${encodeURIComponent(id)}/stop`, { method: 'POST' }),
  deleteBatch: (id) => request(`/batches/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  resumeBatchScheduler: (id, payload = {}) => request(`/batches/${encodeURIComponent(id)}/resume_scheduler`, {
    method: 'POST', body: JSON.stringify(payload),
  }),
  exportBatch: (id, type, format = 'csv') => {
    const url = `${API_BASE}/batches/${encodeURIComponent(id)}/export?type=${type}&format=${format}`;
    window.open(url, '_blank');
  },

  // Work items
  workItemSummary: (params) => request(`/work-items/summary${buildQuery(params)}`),
  listWorkItems: (params) => request(`/work-items${buildQuery(params)}`),
  mutateWorkItems: (action, payload) => request(`/work-items/${action}`, {
    method: 'POST', body: JSON.stringify(payload),
  }),

  // Assets / Results
  listResults: (params) => request(`/results${buildQuery(params)}`),
  updateResultStatus: (id, status) => request(`/results/${encodeURIComponent(id)}/status`, {
    method: 'POST', body: JSON.stringify({ status }),
  }),
  enrichGeoIP: (payload) => request('/assets/enrich-geo', { method: 'POST', body: JSON.stringify(payload) }),

  // Actions & Plan
  listActions: (params) => request(`/actions${buildQuery(params)}`),
  startAction: (payload) => request('/actions', { method: 'POST', body: JSON.stringify(payload) }),
  plan: (params) => request(`/plan${buildQuery(params)}`),

  // Dashboard
  dashboardStats: (params) => request(`/dashboard/stats${buildQuery(params)}`),
  dashboardTrend: (params) => request(`/dashboard/trend${buildQuery(params)}`),
  dashboardHealth: () => request('/dashboard/health'),

  // Stats
  statsSummary: (params) => request(`/stats/summary${buildQuery(params)}`),

  // Policies
  listPolicies: () => request('/policies'),
  createPolicy: (body) => request('/policies', { method: 'POST', body: JSON.stringify(body) }),
  updatePolicy: (id, body) => request(`/policies/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(body) }),
  deletePolicy: (id) => request(`/policies/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // Dicts
  listDicts: () => request('/dicts'),
  getDict: (name) => request(`/dicts/${encodeURIComponent(name)}`),
  appendDict: (name, entries) => request(`/dicts/${encodeURIComponent(name)}`, {
    method: 'POST', body: JSON.stringify({ entries }),
  }),
  deleteDict: (name) => request(`/dicts/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // Fingerprints
  listFingerprints: () => request('/fingerprints'),
  createFingerprint: (body) => request('/fingerprints', { method: 'POST', body: JSON.stringify(body) }),
  deleteFingerprint: (id) => request(`/fingerprints/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // PoCs
  listPoCs: () => request('/pocs'),
  syncPoCs: () => request('/pocs/sync', { method: 'POST' }),

  // Monitors
  listMonitors: () => request('/monitors'),
  createMonitor: (body) => request('/monitors', { method: 'POST', body: JSON.stringify(body) }),
  pauseMonitor: (id) => request(`/monitors/${encodeURIComponent(id)}/pause`, { method: 'POST' }),
  resumeMonitor: (id) => request(`/monitors/${encodeURIComponent(id)}/resume`, { method: 'POST' }),
  deleteMonitor: (id) => request(`/monitors/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // Integrations
  fofaSearch: (query, size = 10) => request('/integrations/fofa/search', {
    method: 'POST', body: JSON.stringify({ query, size }),
  }),
  githubSearch: (keyword) => request('/integrations/github/search', {
    method: 'POST', body: JSON.stringify({ keyword }),
  }),
};

export function splitLines(value) {
  return String(value || '')
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}
