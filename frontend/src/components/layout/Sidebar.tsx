import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/assessment", label: "Assessment" },
  { to: "/scanner", label: "Scanner" },
  { to: "/audit", label: "Audit" },
  { to: "/keys", label: "Keys" },
  { to: "/monitor", label: "Monitoring" },
  { to: "/admin", label: "Admin" },
];

export function Sidebar() {
  return (
    <nav className="w-full sm:w-56 shrink-0 border-b sm:border-b-0 sm:border-r border-slate-200 bg-white sm:min-h-screen p-4">
      <div className="text-lg font-semibold text-slate-900 mb-3 sm:mb-6">ComplyChain</div>
      {/* Horizontal, scrollable strip on phones; vertical list from `sm` up.
          A fixed 224px sidebar consumed 57% of a 390px viewport. */}
      <ul className="flex gap-1 overflow-x-auto sm:block sm:space-y-1 sm:overflow-visible">
        {NAV_ITEMS.map((item) => (
          <li key={item.to} className="shrink-0">
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                `block whitespace-nowrap px-3 py-2 rounded-md text-sm font-medium ${
                  isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
