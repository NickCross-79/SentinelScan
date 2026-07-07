import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./index.css";
import Layout from "./components/Layout";
import { ScanProvider } from "./lib/scanContext";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import Devices from "./pages/Devices";
import Vulnerabilities from "./pages/Vulnerabilities";
import Reports from "./pages/Reports";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "scan", element: <Scan /> },
      { path: "devices", element: <Devices /> },
      { path: "vulnerabilities", element: <Vulnerabilities /> },
      { path: "reports", element: <Reports /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ScanProvider>
      <RouterProvider router={router} />
    </ScanProvider>
  </React.StrictMode>,
);
