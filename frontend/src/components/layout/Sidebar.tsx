import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/assessment", label: "Assessment" },
  { to: "/scanner", label: "Scanner" },
  { to: "/audit", label: "Audit" },
  { to: "/keys", label: "Keys" },
  { to: "/monitor", label: "Monitoring" },
];

export function Sidebar() {
  return (
    <nav className="w-56 shrink-0 border-r border-slate-200 bg-white min-h-screen p-4">
      <div className="text-lg font-semibold text-slate-900 mb-6">ComplyChain</div>
      <ul className="space-y-1">
        {NAV_ITEMS.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm font-medium ${
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
