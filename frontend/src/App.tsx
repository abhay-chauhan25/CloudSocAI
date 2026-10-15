import { NavLink, Route, Routes } from "react-router";

import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { IncidentDetailPage } from "./pages/IncidentDetailPage";
import { IncidentsPage } from "./pages/IncidentsPage";

export function App() {
  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">CloudSOC AI</span>
        <nav>
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/incidents">Incidents</NavLink>
          <NavLink to="/findings">Findings</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/findings/:findingId" element={<FindingDetailPage />} />
          <Route path="*" element={<p className="state">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
