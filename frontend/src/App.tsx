import { Navigate, Route, Routes } from "react-router-dom";
import { ApiKeyGate } from "@/components/ApiKeyGate";
import { Sidebar } from "@/components/layout/Sidebar";
import { AssessmentPage } from "@/pages/AssessmentPage";
import { ScannerPage } from "@/pages/ScannerPage";
import { AuditPage } from "@/pages/AuditPage";
import { KeysPage } from "@/pages/KeysPage";

export default function App() {
  return (
    <ApiKeyGate>
      <div className="flex">
        <Sidebar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<Navigate to="/assessment" replace />} />
            <Route path="/assessment" element={<AssessmentPage />} />
            <Route path="/scanner" element={<ScannerPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/keys" element={<KeysPage />} />
          </Routes>
        </main>
      </div>
    </ApiKeyGate>
  );
}
