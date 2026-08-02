import { ReactNode, useEffect, useState } from "react";
import { Button } from "./ui/Button";
import { Input } from "./ui/Input";
import { Card } from "./ui/Card";
import { getStoredApiKey, setStoredApiKey, registerUnauthorizedHandler } from "@/lib/api";

export function ApiKeyGate({ children }: { children: ReactNode }) {
  const [hasKey, setHasKey] = useState<boolean>(() => !!getStoredApiKey());
  const [draft, setDraft] = useState("");

  useEffect(() => {
    registerUnauthorizedHandler(() => setHasKey(false));
  }, []);

  if (hasKey) return <>{children}</>;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!draft.trim()) return;
    setStoredApiKey(draft.trim());
    setHasKey(true);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <Card className="w-full max-w-sm">
        <h1 className="text-xl font-semibold mb-1">ComplyChain</h1>
        <p className="text-sm text-slate-600 mb-4">Enter your API key to continue.</p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <Input
            type="password"
            placeholder="API key"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            autoFocus
          />
          <Button type="submit" className="w-full">
            Continue
          </Button>
        </form>
      </Card>
    </div>
  );
}
