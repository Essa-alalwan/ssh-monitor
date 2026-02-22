import React, { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import "./Header.css";

function Header({ lastUpdated }) {
  const [localUpdated, setLocalUpdated] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    if (lastUpdated) return;
    const timer = setInterval(() => {
      setLocalUpdated(new Date().toLocaleTimeString());
    }, 10000);
    return () => clearInterval(timer);
  }, [lastUpdated]);

  const shownTime = useMemo(() => lastUpdated || localUpdated, [lastUpdated, localUpdated]);

  return (
    <header className="header">
      <div className="header-inner">
        <div className="header-title">
          <h1>🧠 Raven Security Dashboard</h1>
          <p>Monitoring services: SSH / Web / FTP</p>
          <p className="header-updated">🔄 Last Updated: {shownTime}</p>
        </div>

        <nav className="top-nav" aria-label="Dashboard navigation">
          <NavLink to="/" end className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            Home
          </NavLink>

          <NavLink to="/ssh" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            SSH Logs
          </NavLink>

          <NavLink to="/web" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            Web Traffic
          </NavLink>

          <NavLink to="/ftp" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            FTP Logs
          </NavLink>

          <NavLink to="/nmap" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            Nmap Logs
          </NavLink>

          <NavLink to="/alerts" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            Alerts
          </NavLink>

        </nav>
      </div>
    </header>
  );
}

export default Header;