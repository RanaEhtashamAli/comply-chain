import { Navigate, Route, Routes } from "react-router-dom";
import { ApiKeyGate } from "@/components/ApiKeyGate";
import { Sidebar } from "@/components/layout/Sidebar";
import { AssessmentPage } from "@/pages/AssessmentPage";
import { ScannerPage } from "@/pages/ScannerPage";
import { AuditPage } from "@/pages/AuditPage";
import { KeysPage } from "@/pages/KeysPage";
import { MonitorPage } from "@/pages/MonitorPage";
import { AdminPage } from "@/pages/AdminPage";
import { NotFoundPage } from "@/pages/NotFoundPage";

export default function App() {
  return (
    <ApiKeyGate>
      {/* Column layout on phones, sidebar layout from `sm` up. `min-w-0` on
          main is load-bearing: flex children default to min-width:auto, which
          lets wide tables push the whole page wider instead of scrolling
          inside their own container. */}
      <div className="flex flex-col sm:flex-row min-h-screen">
        <Sidebar />
        <main className="flex-1 min-w-0">
          <Routes>
            <Route path="/" element={<Navigate to="/assessment" replace />} />
            <Route path="/assessment" element={<AssessmentPage />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/keys" element={<KeysPage />} />
            <Route path="/monitor" element={<MonitorPage />} />
            <Route path="/admin" element={<AdminPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
      </div>
    </ApiKeyGate>
  );
}
