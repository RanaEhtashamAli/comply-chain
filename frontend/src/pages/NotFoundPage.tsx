import { Link } from "react-router-dom";
import { Card } from "@/components/ui/Card";

export function NotFoundPage() {
  return (
    <div className="p-4 sm:p-6 max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 mb-4">Page not found</h1>
      <Card>
        <p className="text-sm text-slate-700 mb-3">
          There is nothing at this address. It may have been moved, or the link may be
          out of date.
        </p>
        <Link
          to="/assessment"
          className="text-sm font-medium text-slate-900 underline"
        >
          Go to Assessment
        </Link>
      </Card>
    </div>
  );
}
