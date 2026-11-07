import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppLayout } from './components/AppShell';
import { ToastProvider } from './components/Toast';
import { PreferencesProvider } from './lib/preferences';

import { OverviewScreen } from './screens/Overview';
import { HostsScreen } from './screens/Hosts';
import { HostDetailScreen } from './screens/HostDetail';
import { IncidentsScreen } from './screens/Incidents';
import { IncidentDetailScreen } from './screens/IncidentDetail';
import { DetectionsScreen } from './screens/Detections';
import { AlertDetailScreen } from './screens/AlertDetail';
import { FindingDetailScreen } from './screens/FindingDetail';
import { TimelineScreen } from './screens/Timeline';
import { EvidenceScreen } from './screens/Evidence';
import { ReportsScreen } from './screens/Reports';
import { ReportDetailScreen } from './screens/ReportDetail';
import { SettingsScreen } from './screens/Settings';

export function App() {
  return (
    <PreferencesProvider>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route index element={<OverviewScreen />} />
              <Route path="hosts" element={<HostsScreen />} />
              <Route path="hosts/:id" element={<HostDetailScreen />} />
              <Route path="incidents" element={<IncidentsScreen />} />
              <Route path="incidents/:id" element={<IncidentDetailScreen />} />
              <Route path="detections" element={<DetectionsScreen />} />
              <Route path="alerts/:id" element={<AlertDetailScreen />} />
              <Route path="findings/:id" element={<FindingDetailScreen />} />
              <Route path="timeline" element={<TimelineScreen />} />
              <Route path="evidence" element={<EvidenceScreen />} />
              <Route path="reports" element={<ReportsScreen />} />
              <Route path="reports/:id" element={<ReportDetailScreen />} />
              <Route path="settings" element={<SettingsScreen />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </PreferencesProvider>
  );
}

export default App;

