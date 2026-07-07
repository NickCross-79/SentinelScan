import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

interface ScanCtx {
  activeScanId: string | null;
  setActiveScanId: (id: string | null) => void;
}

const Ctx = createContext<ScanCtx>({ activeScanId: null, setActiveScanId: () => {} });

export function ScanProvider({ children }: { children: ReactNode }) {
  const [activeScanId, setActiveScanId] = useState<string | null>(() =>
    localStorage.getItem("activeScanId"),
  );
  useEffect(() => {
    if (activeScanId) localStorage.setItem("activeScanId", activeScanId);
  }, [activeScanId]);
  return <Ctx.Provider value={{ activeScanId, setActiveScanId }}>{children}</Ctx.Provider>;
}

export const useActiveScan = () => useContext(Ctx);
