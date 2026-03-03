import axios from 'axios';

// Use window.location to dynamically determine API URL
const getApiUrl = () => {
  if (window.REACT_APP_API_URL) {
    return window.REACT_APP_API_URL;
  }
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  const host = window.location.hostname;
  return `http://${host}:7070`;
};

const API_BASE_URL = getApiUrl();

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,  // Send httpOnly cookies automatically
});

const apiV2 = axios.create({
  baseURL: `${API_BASE_URL}/api/v2`,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,  // Send httpOnly cookies automatically
});

const onRequestError = (error) => Promise.reject(error);

// Handle 401 errors (redirect to login)
const on401Response = (error) => {
  if (error.response?.status === 401) {
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
  }
  return Promise.reject(error);
};

// Add interceptors to BOTH v1 and v2
api.interceptors.request.use((config) => config, onRequestError);
api.interceptors.response.use((response) => response, on401Response);

apiV2.interceptors.request.use((config) => config, onRequestError);
apiV2.interceptors.response.use((response) => response, on401Response);

// ============ V1 Endpoints ============

// Scan endpoints
export const startScan = (imageName, skipCache = false) =>
  api.post('/scan', { image_name: imageName, skip_cache: skipCache });
export const getScanResult = (scanId) => api.get(`/scan/${scanId}`);
export const getReport = (scanId) => api.get(`/reports/${scanId}`);

// Batch scan endpoints
export const startBatchScan = (images) => api.post('/scan/batch', { images });
export const getBatchStatus = (batchId) => api.get(`/scan/batch/${batchId}`);

// History endpoint
export const getImageHistory = (imageName, limit = 20) =>
  api.get(`/history/${encodeURIComponent(imageName)}`, { params: { limit } });

// Compare endpoint
export const compareScans = (scanId1, scanId2) => api.get(`/compare/${scanId1}/${scanId2}`);

// Search endpoint
export const searchVulnerabilities = (params) =>
  api.get('/vulnerabilities/search', { params });

// SBOM endpoints
export const getSbomInfo = (scanId) => api.get(`/sbom/${scanId}`);

// Stats endpoint
export const getStats = () => api.get('/stats');

// Recent scans (from history)
export const getRecentScans = (limit = 5) => api.get('/scans/recent', { params: { limit } });

// API info
export const getApiInfo = () => api.get('/api-info');

// Health check
export const healthCheck = () => axios.get(`${API_BASE_URL}/health`, { withCredentials: true });

// ============ V2 Enterprise Endpoints ============

// Auth
export const logoutApi = () => apiV2.post('/auth/logout');

// Scheduled Scans
export const getSchedules = () => apiV2.get('/schedules');
export const createSchedule = (data) => apiV2.post('/schedules', data);
export const getSchedule = (name) => apiV2.get(`/schedules/${name}`);
export const updateSchedule = (name, data) => apiV2.put(`/schedules/${name}`, data);
export const deleteSchedule = (name) => apiV2.delete(`/schedules/${name}`);
export const runScheduleNow = (name) => apiV2.post(`/schedules/${name}/run`);

// Base Image Tracking
export const getBaseImages = () => apiV2.get('/base-images');
export const registerBaseImage = (data) => apiV2.post('/base-images', data);
export const getBaseImageHistory = (imageName, tag, limit = 30) =>
  apiV2.get('/base-images/history', { params: { image_name: imageName, tag, limit } });
export const compareBaseImages = (image1, tag1, image2, tag2) =>
  apiV2.get('/base-images/compare', { params: { image1, tag1, image2, tag2 } });
export const scanAllBaseImages = () => apiV2.post('/base-images/scan-all');
export const deleteBaseImage = (imageName, tag) =>
  apiV2.delete('/base-images/remove', { params: { image_name: imageName, tag } });
export const updateBaseImage = (imageName, tag, data) =>
  apiV2.put('/base-images/update', data, { params: { image_name: imageName, tag } });
export const getBaseImageDetails = (imageName, tag) =>
  apiV2.get('/base-images/details', { params: { image_name: imageName, tag } });

// CVSS Enrichment
export const getCvssEnriched = (scanId) => apiV2.get(`/scan/${scanId}/cvss`);

// Trends
export const getImageTrends = (imageName, days = 30) =>
  apiV2.get(`/trends/image/${encodeURIComponent(imageName)}`, { params: { days } });
export const getGlobalTrends = (days = 30) => apiV2.get('/trends/global', { params: { days } });
export const getTopVulnerable = (days = 7, limit = 10) =>
  apiV2.get('/trends/top-vulnerable', { params: { days, limit } });
export const getVulnDistribution = (days = 30) =>
  apiV2.get('/trends/distribution', { params: { days } });

// Exports
export const exportCsv = (scanId) =>
  apiV2.get(`/export/${scanId}/csv`, { responseType: 'blob' });
export const exportSbomCsv = (scanId) =>
  apiV2.get(`/export/${scanId}/sbom-csv`, { responseType: 'blob' });
export const exportExecutivePdf = (scanId, includeDetails = false) =>
  apiV2.get(`/export/${scanId}/pdf`, {
    params: { include_details: includeDetails },
    responseType: 'blob'
  });
export const exportDetailedPdf = (scanId) =>
  apiV2.get(`/export/${scanId}/detailed-pdf`, { responseType: 'blob' });

// Notifications
export const testNotification = (webhookUrl) =>
  apiV2.post('/test-notification', { webhook_url: webhookUrl });

// Dependency Graph
export const getDependencyGraph = (scanId) =>
  apiV2.get(`/scan/${scanId}/dependency-graph`);
export const getPackageImpact = (scanId, packageName) =>
  apiV2.get(`/scan/${scanId}/package-impact/${packageName}`);

// Remediation
export const getRemediationPlan = (scanId) =>
  apiV2.get(`/scan/${scanId}/remediation`);
export const getQuickWins = (scanId) =>
  apiV2.get(`/scan/${scanId}/quick-wins`);
export const getRemediationScript = (scanId, packageType = null) =>
  apiV2.get(`/scan/${scanId}/remediation-script`, {
    params: packageType ? { package_type: packageType } : {},
    responseType: 'blob'
  });

// Risk Scoring
export const getRiskScore = (scanId) =>
  apiV2.get(`/scan/${scanId}/risk-score`);
export const getRiskWeights = () =>
  apiV2.get('/risk-weights');
export const updateRiskWeights = (weights) =>
  apiV2.put('/risk-weights', weights);

// EPSS/KEV Enrichment
export const getEnrichedVulnerabilities = (scanId, params = {}) =>
  apiV2.get(`/scan/${scanId}/enriched`, { params });
export const getKevMatches = (scanId) =>
  apiV2.get(`/scan/${scanId}/kev-matches`);
export const getHighRiskVulns = (scanId) =>
  apiV2.get(`/scan/${scanId}/high-risk`);
export const getKevStatus = () =>
  apiV2.get('/kev/status');
export const checkCveInKev = (cveId) =>
  apiV2.get(`/kev/check/${cveId}`);
export const lookupEpssScores = (cveIds) =>
  apiV2.post('/epss/lookup', cveIds);

// System Status & Updates
export const getToolVersions = () =>
  apiV2.get('/system/tool-versions');
export const getDbStatus = () =>
  apiV2.get('/system/db-status');
export const triggerDbUpdate = () =>
  apiV2.post('/system/update-db');
export const refreshSystemStatus = () =>
  apiV2.post('/system/refresh-status');
export const getUpdateHistory = (limit = 20) =>
  apiV2.get('/system/update-history', { params: { limit } });
export const getSystemNotifications = (limit = 20) =>
  apiV2.get('/system/notifications', { params: { limit } });

// Worker Monitoring
export const getWorkersStatus = () =>
  apiV2.get('/workers/status');
export const getQueueStats = () =>
  apiV2.get('/workers/queues');
export const getWorkersList = () =>
  apiV2.get('/workers/list');
export const getAutoscalerStatus = () =>
  apiV2.get('/workers/autoscaler');
export const getScalingHistory = (limit = 20) =>
  apiV2.get('/workers/scaling-history', { params: { limit } });
export const getTaskStats = () =>
  apiV2.get('/workers/tasks');
export const pingWorkers = () =>
  apiV2.post('/workers/ping');
export const purgeQueue = (queueName) =>
  apiV2.delete(`/workers/queues/${queueName}`);
export const getWorkersHealth = () =>
  apiV2.get('/workers/health');

// API Key Management
export const createApiKey = (name, expiresDays = 365) =>
  apiV2.post('/api-keys', { name, expires_days: expiresDays });
export const listApiKeys = () =>
  apiV2.get('/api-keys');
export const revokeApiKey = (keyId) =>
  apiV2.delete(`/api-keys/${keyId}`);

// WebSocket URL
export const getWsUrl = (scanId) => {
  const host = window.location.hostname;
  return `ws://${host}:7070/api/v2/ws/scan/${scanId}`;
};

export const getGlobalWsUrl = () => {
  const host = window.location.hostname;
  return `ws://${host}:7070/api/v2/ws/global`;
};

export default api;
