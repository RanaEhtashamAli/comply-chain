import { HTMLAttributes } from "react";

export function Card({ className = "", ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`bg-white text-slate-900 border border-slate-200 rounded-lg shadow-sm p-4 ${className}`}
      {...props}
    />
  );
}
