import { useEffect, useState } from 'react'

interface Incident {
  id: number
  timestamp: string
  resource_id: string
  event_type: string
  details: string
  cis_control: string | null
  gdpr_control: string | null
  dpdpa_control: string | null
  iso_control: string | null
}

interface Metrics {
  monitored_assets: number
  active_drifts: number
  critical_risks: number
  privacy_violations: number
}

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('http://localhost:8000/api/metrics')
      .then(res => res.json())
      .then(data => setMetrics(data))
      .catch(err => console.error("Error fetching metrics:", err))

    fetch('http://localhost:8000/api/incidents')
      .then(res => res.json())
      .then(data => {
        setIncidents(data)
        if (data.length > 0) setSelectedIncident(data[0]) 
        setLoading(false)
      })
      .catch(err => console.error("Error fetching incidents:", err))
  }, [])

  const formatDetails = (detailsStr: string) => {
    try {
      const obj = JSON.parse(detailsStr)
      return JSON.stringify(obj, null, 2)
    } catch {
      return detailsStr
    }
  }

  const getThreatContext = (incident: Incident) => {
    const text = incident.details.toLowerCase()
    if (text.includes("22") || text.includes("ssh")) {
      return "SSH Port 22 was modified to allow inbound connections from 0.0.0.0/0. High probability of brute-force attacks and unauthorized access."
    }
    if (text.includes("5432") || text.includes("3306")) {
      return "Public access block removed for critical database/management port. Exposes highly sensitive data archives to public read access. Violates strict least privilege architecture."
    }
    return "Network access rules modified outside of approved baseline. High probability of unauthorized lateral movement."
  }

  return (
    <div className="font-body-lg text-body-lg overflow-hidden h-screen w-screen flex antialiased bg-[#09090b]">
      
      {/* COMPACT SIDEBAR: Reduced from w-64 to w-56 */}
      <nav className="fixed left-0 top-0 h-full flex flex-col w-56 bg-surface-container-lowest border-r border-outline-variant z-20 shrink-0">
        <div className="p-5 border-b border-outline-variant flex flex-col gap-1">
          <h1 className="font-headline text-[18px] font-black text-primary tracking-tighter">DRIFTWATCH</h1>
          <span className="font-label-mono text-[10px] text-on-surface-variant uppercase">Cloud Security</span>
        </div>
        <div className="p-4">
          <button className="w-full bg-primary-container text-[#000000] font-headline text-body-sm font-semibold py-2 px-4 rounded-none border border-primary-container hover:bg-[#4cd7f6] transition-colors flex items-center justify-center gap-2">
            <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>radar</span>
            Quick Scan
          </button>
        </div>
        <div className="flex-1 overflow-y-auto custom-scrollbar py-2">
          <ul className="flex flex-col gap-1">
            <li>
              <a className="flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all font-body-sm text-body-sm active:opacity-80" href="#">
                <span className="material-symbols-outlined text-[20px]">dashboard</span> Overview
              </a>
            </li>
            <li>
              <a className="flex items-center gap-3 px-4 py-2 text-primary bg-surface-container-low border-l-2 border-primary hover:bg-surface-container-high hover:text-on-surface transition-all font-body-sm text-body-sm active:opacity-80" href="#">
                <span className="material-symbols-outlined text-[20px]" style={{ fontVariationSettings: "'FILL' 1" }}>security</span> Incidents
              </a>
            </li>
            <li>
              <a className="flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all font-body-sm text-body-sm active:opacity-80" href="#">
                <span className="material-symbols-outlined text-[20px]">inventory_2</span> Assets
              </a>
            </li>
            <li>
              <a className="flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all font-body-sm text-body-sm active:opacity-80" href="#">
                <span className="material-symbols-outlined text-[20px]">fact_check</span> Frameworks
              </a>
            </li>
            <li>
              <a className="flex items-center gap-3 px-4 py-2 text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all font-body-sm text-body-sm active:opacity-80" href="#">
                <span className="material-symbols-outlined text-[20px]">settings</span> Settings
              </a>
            </li>
          </ul>
        </div>
        <div className="border-t border-outline-variant p-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-surface-container-high rounded-full overflow-hidden border border-outline-variant shrink-0">
              <img alt="User Profile" className="w-full h-full object-cover" src="https://ui-avatars.com/api/?name=Admin+User&background=2a2a2c&color=4cd7f6" />
            </div>
            <div className="flex flex-col truncate">
              <span className="font-body-sm text-body-sm text-on-surface truncate">Admin User</span>
              <span className="font-label-mono text-[10px] text-on-surface-variant">ID: 8902-A</span>
            </div>
          </div>
        </div>
      </nav>

      {/* MAIN WRAPPER: Matches new w-56 sidebar width */}
      <div className="flex-1 ml-56 flex flex-col h-full min-w-0">
        
        {/* RESPONSIVE HEADER */}
        <header className="h-14 bg-surface-container-lowest border-b border-outline-variant flex justify-between items-center w-full px-4 z-10 shrink-0">
          <div className="flex items-center gap-3 shrink-0">
            <h2 className="font-headline text-[16px] font-black text-primary">DriftWatch</h2>
            <div className="h-4 w-px bg-outline-variant mx-1 hidden lg:block"></div>
            {/* Hidden on small screens to prevent overflow */}
            <span className="font-label-caps text-[10px] text-on-surface uppercase tracking-widest hidden xl:block">Cloud Security Posture Management</span>
          </div>
          
          <div className="flex items-center gap-2 md:gap-4 overflow-hidden">
            <div className="hidden md:flex gap-4 shrink-0">
              <a className="font-label-caps text-[11px] text-on-surface-variant hover:text-primary transition-colors uppercase" href="#">Dashboard</a>
              <a className="font-label-caps text-[11px] text-primary border-b-2 border-primary pb-1 uppercase" href="#">Reports</a>
            </div>
            <div className="flex items-center gap-2 md:gap-3 border-l border-outline-variant pl-3 md:pl-4 shrink-0">
              <div className="hidden lg:flex items-center gap-2 bg-[rgba(6,182,212,0.1)] border border-primary px-2 py-1">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
                <span className="font-label-mono text-[10px] text-primary whitespace-nowrap">Monitoring: AWS us-east-1</span>
              </div>
              <button className="bg-primary-container text-[#000000] font-label-caps text-[10px] px-3 py-1.5 hover:bg-[#4cd7f6] transition-colors border border-primary-container">REMEDIATE</button>
              <button className="border border-[#27272a] text-on-surface font-label-caps text-[10px] px-3 py-1.5 hover:border-outline transition-colors">EXPORT</button>
            </div>
          </div>
        </header>

        {/* Scrollable Dashboard Content */}
        <main className="flex-1 overflow-y-auto custom-scrollbar p-4 lg:p-6 flex flex-col gap-4 lg:gap-6 min-w-0">
          
          {/* Executive Metrics Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
            <div className="bg-[#18181b] border border-[#27272a] p-4 flex flex-col justify-between h-28 hover:border-primary-container transition-colors group">
              <div className="flex justify-between items-start">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Monitored Assets</span>
                <span className="material-symbols-outlined text-outline group-hover:text-primary-container transition-colors text-[18px]">dns</span>
              </div>
              <div className="flex items-end justify-between">
                <span className="font-display text-[24px] text-on-surface font-bold">{metrics?.monitored_assets || 0}</span>
              </div>
            </div>
            
            <div className="bg-[#18181b] border border-[#27272a] p-4 flex flex-col justify-between h-28 hover:border-primary-container transition-colors group relative overflow-hidden">
              <div className="absolute top-0 left-0 w-0.5 h-full bg-primary-container"></div>
              <div className="flex justify-between items-start pl-2">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Active Drifts</span>
                <span className="material-symbols-outlined text-outline group-hover:text-primary-container transition-colors text-[18px]">route</span>
              </div>
              <div className="flex items-end justify-between pl-2">
                <span className="font-display text-[24px] text-on-surface font-bold">{metrics?.active_drifts || 0}</span>
                <div className="flex items-center gap-1 text-error font-label-mono text-[11px]">
                  <span className="material-symbols-outlined text-[14px]">arrow_upward</span><span>+{metrics?.active_drifts || 0}</span>
                </div>
              </div>
            </div>
            
            <div className="bg-[#18181b] border border-[#27272a] p-4 flex flex-col justify-between h-28 hover:border-error transition-colors group relative overflow-hidden">
              <div className="absolute top-0 left-0 w-0.5 h-full bg-error"></div>
              <div className="flex justify-between items-start pl-2">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Critical Infra Risks</span>
                <span className="material-symbols-outlined text-error group-hover:animate-pulse transition-colors text-[18px]">warning</span>
              </div>
              <div className="flex items-end justify-between pl-2">
                <span className="font-display text-[24px] text-error font-bold">{metrics?.critical_risks || 0}</span>
                <div className="bg-[rgba(244,63,94,0.1)] border border-error text-error px-2 py-0.5 font-label-mono text-[10px] flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-error rounded-full animate-ping"></span> Urgent
                </div>
              </div>
            </div>
            
            <div className="bg-[#18181b] border border-[#27272a] p-4 flex flex-col justify-between h-28 hover:border-error transition-colors group relative overflow-hidden">
              <div className="absolute top-0 left-0 w-0.5 h-full bg-error"></div>
              <div className="flex justify-between items-start pl-2">
                <span className="font-label-caps text-[10px] text-on-surface-variant uppercase">Privacy Violations</span>
                <span className="material-symbols-outlined text-error text-[18px]">policy</span>
              </div>
              <div className="flex items-end justify-between pl-2">
                <span className="font-display text-[24px] text-error font-bold">{metrics?.privacy_violations || 0}</span>
              </div>
            </div>
          </div>

          {/* Incident Management Section */}
          <div className="flex-1 flex gap-4 lg:gap-6 h-full min-h-0 overflow-hidden">
            
            {/* Left Column: Data Table */}
            <div className="flex-1 flex flex-col bg-[#18181b] border border-[#27272a] overflow-hidden min-w-0">
              <div className="p-3 border-b border-[#27272a] flex justify-between items-center bg-[#131315]">
                <div className="flex items-center gap-3 flex-1">
                  <div className="relative w-full max-w-xs">
                    <span className="material-symbols-outlined absolute left-2 top-1/2 -translate-y-1/2 text-outline-variant text-[16px]">search</span>
                    <input className="w-full bg-[#09090b] border border-[#27272a] text-on-surface text-[12px] py-1.5 pl-8 pr-3 focus:border-primary-container outline-none transition-colors h-8" placeholder="Search ID..." type="text" />
                  </div>
                  <div className="relative w-36 hidden md:block">
                    <select className="w-full bg-[#09090b] border border-[#27272a] text-on-surface text-[12px] py-1.5 px-3 appearance-none focus:border-primary-container outline-none transition-colors h-8 cursor-pointer">
                      <option value="all">All Frameworks</option>
                      <option value="gdpr">GDPR</option>
                    </select>
                  </div>
                </div>
              </div>
              
              {/* Added min-w-[500px] to allow horizontal scroll on super small screens instead of breaking flex */}
              <div className="flex-1 overflow-auto custom-scrollbar">
                <table className="w-full text-left border-collapse min-w-[500px]">
                  <thead className="sticky top-0 bg-[#131315] z-10 shadow-[0_1px_0_#27272a]">
                    <tr>
                      <th className="py-2 px-3 font-label-caps text-[10px] text-on-surface-variant uppercase whitespace-nowrap">Timestamp</th>
                      <th className="py-2 px-3 font-label-caps text-[10px] text-on-surface-variant uppercase">Resource ID</th>
                      <th className="py-2 px-3 font-label-caps text-[10px] text-on-surface-variant uppercase whitespace-nowrap">Event Type</th>
                      <th className="py-2 px-3 font-label-caps text-[10px] text-on-surface-variant uppercase text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="font-data-mono text-[12px] text-on-surface divide-y divide-[#27272a]">
                    {loading ? (
                      <tr><td colSpan={4} className="p-4 text-center">Loading infrastructure data...</td></tr>
                    ) : incidents.map(incident => (
                      <tr 
                        key={incident.id} 
                        onClick={() => setSelectedIncident(incident)}
                        className={`transition-colors cursor-pointer group ${selectedIncident?.id === incident.id ? 'bg-[#1c1c1f] border-l-2 border-l-primary-container' : 'hover:bg-[#1c1c1f] border-l-2 border-l-transparent'}`}
                      >
                        <td className="py-3 px-3 text-outline whitespace-nowrap">{incident.timestamp.substring(0, 19)}Z</td>
                        <td className={`py-3 px-3 truncate max-w-[150px] ${selectedIncident?.id === incident.id ? 'text-primary-container' : 'text-on-surface'}`}>{incident.resource_id}</td>
                        <td className="py-3 px-3 flex items-center gap-2 whitespace-nowrap">
                          <span className="w-2 h-2 bg-error rounded-none shrink-0"></span>
                          {incident.event_type}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button className={`${selectedIncident?.id === incident.id ? 'text-primary-container border-primary-container' : 'text-on-surface-variant border-transparent'} group-hover:text-primary-container transition-colors uppercase font-label-caps text-[10px] tracking-wider border px-2 py-1`}>
                            {selectedIncident?.id === incident.id ? 'DETAILS' : 'VIEW'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* COMPACT DETAIL PANEL: Reduced from w-[480px] to w-[360px] */}
            {selectedIncident && (
              <div className="w-[360px] bg-[#1c1c1f] border border-[#3f3f46] flex flex-col shrink-0 relative overflow-hidden shadow-2xl">
                <div className="h-1 w-full bg-error absolute top-0 left-0"></div>
                <div className="p-4 border-b border-[#3f3f46] flex justify-between items-start pt-5">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="bg-[rgba(244,63,94,0.1)] border border-error text-error px-2 py-0.5 font-label-caps text-[9px] uppercase tracking-wider shrink-0">Critical Drift</span>
                    </div>
                    <h3 className="font-headline text-[14px] font-semibold text-on-surface truncate mt-2" title={selectedIncident.resource_id}>{selectedIncident.resource_id}</h3>
                    <p className="font-data-mono text-[10px] text-on-surface-variant mt-1 truncate">Event: {selectedIncident.event_type}</p>
                  </div>
                  <button className="text-on-surface-variant hover:text-on-surface shrink-0 ml-2" onClick={() => setSelectedIncident(null)}>
                    <span className="material-symbols-outlined text-[18px]">close</span>
                  </button>
                </div>
                
                <div className="flex-1 overflow-y-auto custom-scrollbar p-4 flex flex-col gap-5">
                  <section>
                    <h4 className="font-label-caps text-[10px] text-on-surface-variant uppercase mb-2 flex items-center gap-2 border-b border-[#3f3f46] pb-1">
                      <span className="material-symbols-outlined text-outline text-[14px]">radar</span> Threat Context
                    </h4>
                    <p className="font-body-sm text-[13px] text-on-surface leading-relaxed">{getThreatContext(selectedIncident)}</p>
                  </section>
                  
                  <section>
                    <h4 className="font-label-caps text-[10px] text-on-surface-variant uppercase mb-2 flex items-center gap-2 border-b border-[#3f3f46] pb-1">
                      <span className="material-symbols-outlined text-outline text-[14px]">code</span> Configuration Diff
                    </h4>
                    <div className="bg-[#000000] border border-[#27272a] p-3 w-full overflow-hidden">
                      {/* Added whitespace-pre-wrap to force long JSON strings to wrap instead of breaking the panel */}
                      <pre className="font-label-mono text-primary-container text-[11px] leading-relaxed whitespace-pre-wrap break-all">
                        {formatDetails(selectedIncident.details)}
                      </pre>
                    </div>
                  </section>
                  
                  <section>
                    <h4 className="font-label-caps text-[10px] text-on-surface-variant uppercase mb-2 flex items-center gap-2 border-b border-[#3f3f46] pb-1">
                      <span className="material-symbols-outlined text-outline text-[14px]">build</span> Actionable Remediation
                    </h4>
                    <div className="bg-[#131315] border border-[#27272a] p-3 font-body-sm text-on-surface text-[12px]">
                      <ol className="list-decimal list-inside space-y-1">
                        <li>Verify auth in CloudTrail.</li>
                        <li>Re-apply baseline IaC.</li>
                        <li>Lock IAM role pending review.</li>
                      </ol>
                    </div>
                  </section>
                </div>
                
                <div className="p-3 border-t border-[#3f3f46] bg-[#131315] flex justify-end gap-2 shrink-0">
                  <button className="border border-[#3f3f46] text-on-surface font-label-caps text-[9px] px-3 py-2 hover:bg-[#27272a] transition-colors">IGNORE</button>
                  <button className="bg-primary-container text-[#000000] font-label-caps text-[9px] px-3 py-2 hover:bg-[#4cd7f6] transition-colors border border-primary-container flex items-center gap-1">
                    <span className="material-symbols-outlined text-[14px]">auto_fix_high</span> REMEDIATE
                  </button>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}

export default App