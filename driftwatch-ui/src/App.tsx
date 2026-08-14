import { useState, useEffect } from 'react'

interface Incident {
  id: number
  timestamp: string
  resource_id: string
  event_type: string
  details: string
  violation_trigger?: string
  cis_control?: string
  iso_control?: string
  gdpr_control?: string
  dpdpa_control?: string
}

interface Metric {
  monitored_assets: number
  active_drifts: number
  critical_risks: number
  privacy_violations: number
}

interface Control {
  id: number
  framework: string
  control_id: string
  description: string
  risk_level: string
  trigger_condition: string
}

// Define valid framework keys and configuration for dynamic rendering
type FrameworkKey = 'CIS' | 'ISO 27001' | 'GDPR' | 'DPDPA'

const frameworkConfig: Record<FrameworkKey, { label: string, db_key: keyof Incident }> = {
  'CIS': { label: 'Benchmark Deviation', db_key: 'cis_control' },
  'ISO 27001': { label: 'Non-Conformity', db_key: 'iso_control' },
  'GDPR': { label: 'Privacy Violation', db_key: 'gdpr_control' },
  'DPDPA': { label: 'Data Protection Breach', db_key: 'dpdpa_control' }
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'incidents' | 'assets' | 'frameworks' | 'settings'>('incidents')
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [frameworks, setFrameworks] = useState<Control[]>([])
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [frameworkFilter, setFrameworkFilter] = useState<string>('All') 
  const [activeFramework, setActiveFramework] = useState<FrameworkKey>('CIS') // NEW: Global Framework Switcher State
  
  const [metrics, setMetrics] = useState<Metric>({
    monitored_assets: 0,
    active_drifts: 0,
    critical_risks: 0,
    privacy_violations: 0
  })

  const fetchData = async () => {
    try {
      const resMetrics = await fetch('http://localhost:8000/api/metrics')
      if (resMetrics.ok) {
        const data = await resMetrics.json()
        setMetrics(data)
      }

      const resIncidents = await fetch('http://localhost:8000/api/incidents')
      if (resIncidents.ok) {
        const data = await resIncidents.json()
        setIncidents(data)
        if (data.length > 0 && !selectedIncident) {
          setSelectedIncident(data[0])
        }
      }

      const resFrameworks = await fetch('http://localhost:8000/api/frameworks')
      if (resFrameworks.ok) {
        const data = await resFrameworks.json()
        setFrameworks(data)
      }
    } catch (err) {
      console.error('Error fetching API data:', err)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleQuickScan = async () => {
    setIsScanning(true)
    try {
      await fetch('http://localhost:8000/api/scan', { method: 'POST' })
      await fetchData()
    } catch (err) {
      console.error('Scan failed:', err)
    } finally {
      setIsScanning(false)
    }
  }

  const formatTimestamp = (isoString: string) => {
    if (!isoString) return 'N/A'
    const date = new Date(isoString)
    return date.toLocaleString('en-IN', {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    })
  }

  const formatDetails = (detailsStr: string) => {
    try {
      const parsed = JSON.parse(detailsStr)
      return JSON.stringify(parsed, null, 2)
    } catch {
      return detailsStr
    }
  }

  const getThreatContext = (incident: Incident) => {
    const text = incident.details.toLowerCase()
    if (text.includes("22") || text.includes("ssh")) {
      return "SSH Port 22 was modified to allow inbound connections from 0.0.0.0/0. High probability of brute-force attacks and unauthorized access."
    }
    if (text.includes("3389") || text.includes("rdp")) {
      return "RDP Port 3389 open publicly. Extreme risk of remote takeover attacks."
    }
    return "Network access rules modified outside of approved baseline. Potential data exposure."
  }

  const getAssetClass = (resId: string) => {
    if (resId.startsWith('sg-') || resId.startsWith('i-')) return 'EC2 / Compute'
    if (resId.includes('policy') || resId.includes('user') || resId.includes('role')) return 'IAM / Identity'
    if (resId.includes('bucket')) return 'S3 / Storage'
    if (resId.includes('rds') || resId.includes('db')) return 'RDS / Database'
    return 'AWS Resource'
  }

  const filteredIncidents = incidents.filter(item =>
    item.resource_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.event_type.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="font-body-lg text-body-lg overflow-hidden h-screen w-screen flex antialiased bg-[#09090b] text-white">
      {/* SIDEBAR NAVIGATION */}
      <nav className="fixed left-0 top-0 h-full flex flex-col w-56 bg-[#131315] border-r border-[#27272a] z-20 shrink-0">
        <div className="p-5 border-b border-[#27272a] flex flex-col gap-1">
          <h1 className="font-headline text-[18px] font-black text-[#38bdf8] tracking-tighter">DRIFTWATCH</h1>
          <span className="font-label-mono text-[10px] text-[#a1a1aa] uppercase">Cloud Security</span>
        </div>

        {/* QUICK SCAN BUTTON */}
        <div className="p-4">
          <button
            onClick={handleQuickScan}
            disabled={isScanning}
            className={`w-full py-2.5 px-3 font-label-caps text-[11px] uppercase tracking-wider flex items-center justify-center gap-2 transition-all font-bold ${
              isScanning
                ? 'bg-[#27272a] text-[#a1a1aa] cursor-not-allowed'
                : 'bg-[#00f0ff] text-[#000000] hover:bg-[#38bdf8] shadow-[0_0_15px_rgba(0,240,255,0.3)]'
            }`}
          >
            <span className={`material-symbols-outlined text-[16px] ${isScanning ? 'animate-spin' : ''}`}>
              {isScanning ? 'sync' : 'radar'}
            </span>
            {isScanning ? 'Scanning AWS...' : 'Quick Scan'}
          </button>
        </div>

        {/* MENU ITEMS */}
        <div className="flex-1 px-3 py-2 space-y-1">
          {[
            { id: 'overview', label: 'Overview', icon: 'dashboard' },
            { id: 'incidents', label: 'Incidents', icon: 'shield' },
            { id: 'assets', label: 'Assets', icon: 'inventory_2' },
            { id: 'frameworks', label: 'Frameworks', icon: 'fact_check' },
            { id: 'settings', label: 'Settings', icon: 'settings' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`w-full flex items-center gap-3 px-3 py-2 text-[13px] font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-[#27272a] text-[#38bdf8] border-l-2 border-[#38bdf8]'
                  : 'text-[#a1a1aa] hover:text-white hover:bg-[#1c1c1f]'
              }`}
            >
              <span className="material-symbols-outlined text-[18px]">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* USER PROFILE */}
        <div className="p-3 border-t border-[#27272a] flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-[#27272a] flex items-center justify-center font-bold text-[11px] text-[#38bdf8]">AU</div>
          <div className="min-w-0">
            <p className="text-[12px] font-semibold text-white truncate">Admin User</p>
            <p className="text-[10px] text-[#a1a1aa] font-mono truncate">ID: 8902-A</p>
          </div>
        </div>
      </nav>

      {/* MAIN CONTENT AREA */}
      <main className="pl-56 flex-1 flex flex-col h-full bg-[#09090b] overflow-hidden">
        {/* TOP HEADER */}
        <header className="h-14 border-b border-[#27272a] px-6 flex items-center justify-between shrink-0 bg-[#09090b]">
          <div className="flex items-center gap-3">
            <h2 className="font-headline text-[16px] font-bold text-white uppercase">{activeTab}</h2>
            <span className="text-[11px] text-[#71717a] font-mono">| CLOUD SECURITY POSTURE MANAGEMENT</span>
          </div>
          
          {/* UPDATED: HEADER ACTIONS WITH FRAMEWORK SWITCHER */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-[#a1a1aa] uppercase tracking-wider">Framework:</span>
              <select
                className="bg-[#131315] text-[#38bdf8] border border-[#27272a] px-2 py-1 text-[11px] font-mono rounded-sm focus:outline-none focus:border-[#38bdf8] cursor-pointer"
                value={activeFramework}
                onChange={(e) => setActiveFramework(e.target.value as FrameworkKey)}
              >
                {(Object.keys(frameworkConfig) as FrameworkKey[]).map(fw => (
                  <option key={fw} value={fw}>{fw}</option>
                ))}
              </select>
            </div>

            <span className="px-2.5 py-1 bg-[#131315] border border-[#27272a] text-[#38bdf8] text-[10px] font-mono flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#00f0ff] animate-pulse"></span>
              Monitoring: AWS us-east-1
            </span>
          </div>
        </header>

        {/* METRICS METERS */}
        <div className="p-6 pb-2 grid grid-cols-4 gap-4 shrink-0">
          <div className="bg-[#131315] border border-[#27272a] p-4">
            <p className="text-[10px] font-mono text-[#a1a1aa] uppercase">Monitored Assets</p>
            <p className="text-[24px] font-bold text-white mt-1">{metrics.monitored_assets}</p>
          </div>
          <div className="bg-[#131315] border border-[#27272a] p-4">
            <p className="text-[10px] font-mono text-[#a1a1aa] uppercase">Active Drifts</p>
            <p className="text-[24px] font-bold text-[#38bdf8] mt-1">{metrics.active_drifts}</p>
          </div>
          <div className="bg-[#131315] border border-[#27272a] p-4 border-l-2 border-l-[#f43f5e]">
            <p className="text-[10px] font-mono text-[#a1a1aa] uppercase">Critical Risks</p>
            <p className="text-[24px] font-bold text-[#f43f5e] mt-1">{metrics.critical_risks}</p>
          </div>
          <div className="bg-[#131315] border border-[#27272a] p-4 border-l-2 border-l-[#fb7185]">
            <p className="text-[10px] font-mono text-[#a1a1aa] uppercase">Privacy Violations</p>
            <p className="text-[24px] font-bold text-white mt-1">{metrics.privacy_violations}</p>
          </div>
        </div>

        {/* TAB CONTENT VIEWS */}
        <div className="flex-1 p-6 overflow-hidden flex">
          
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="w-full space-y-4 overflow-y-auto">
              <div className="bg-[#131315] border border-[#27272a] p-6">
                <h3 className="text-[14px] font-bold text-[#38bdf8] uppercase mb-2">Posture Health Summary</h3>
                <p className="text-[13px] text-[#a1a1aa]">
                  DriftWatch is continuously monitoring your cloud infrastructure against 40 standard security policies across CIS, ISO 27001, GDPR, and DPDPA frameworks.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#131315] border border-[#27272a] p-5">
                  <h4 className="text-[12px] font-mono uppercase text-white mb-3">Compliance Coverage</h4>
                  <ul className="space-y-2 text-[12px] text-[#a1a1aa]">
                    <li className="flex justify-between"><span>CIS Foundations</span><span className="text-[#38bdf8]">10 Rules Active</span></li>
                    <li className="flex justify-between"><span>ISO/IEC 27001</span><span className="text-[#38bdf8]">10 Rules Active</span></li>
                    <li className="flex justify-between"><span>GDPR Privacy</span><span className="text-[#38bdf8]">10 Rules Active</span></li>
                    <li className="flex justify-between"><span>DPDPA (India)</span><span className="text-[#38bdf8]">10 Rules Active</span></li>
                  </ul>
                </div>
                <div className="bg-[#131315] border border-[#27272a] p-5">
                  <h4 className="text-[12px] font-mono uppercase text-white mb-3">System Engine Status</h4>
                  <p className="text-[12px] text-[#a1a1aa]">Scanner: <span className="text-[#00f0ff]">boto3 AWS Engine</span></p>
                  <p className="text-[12px] text-[#a1a1aa] mt-1">Database: <span className="text-white">SQLite (driftwatch.db)</span></p>
                  <p className="text-[12px] text-[#a1a1aa] mt-1">API Backend: <span className="text-white">FastAPI Active</span></p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: INCIDENTS */}
          {activeTab === 'incidents' && (
            <div className="flex-1 flex gap-4 overflow-hidden">
              <div className="flex-1 bg-[#131315] border border-[#27272a] flex flex-col overflow-hidden">
                <div className="p-3 border-b border-[#27272a] bg-[#09090b]">
                  <input
                    type="text"
                    placeholder="Search Resource ID..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-64 bg-[#131315] border border-[#27272a] px-3 py-1.5 text-[12px] text-white focus:outline-none focus:border-[#38bdf8]"
                  />
                </div>
                <div className="flex-1 overflow-y-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead className="bg-[#09090b] text-[#a1a1aa] uppercase font-mono text-[10px] sticky top-0 border-b border-[#27272a]">
                      <tr>
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Resource ID</th>
                        <th className="p-3">Event Type</th>
                        <th className="p-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#27272a]">
                      {filteredIncidents.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="p-8 text-center text-[#71717a] font-mono">
                            No security drift events detected. Click "Quick Scan" to query AWS.
                          </td>
                        </tr>
                      ) : (
                        filteredIncidents.map(item => (
                          <tr
                            key={item.id}
                            onClick={() => setSelectedIncident(item)}
                            className={`cursor-pointer transition-colors ${
                              selectedIncident?.id === item.id ? 'bg-[#1c1c1f] text-[#38bdf8]' : 'hover:bg-[#131315] text-[#a1a1aa]'
                            }`}
                          >
                            <td className="p-3 font-mono whitespace-nowrap">{formatTimestamp(item.timestamp)}</td>
                            <td className="p-3 font-semibold text-white">{item.resource_id}</td>
                            <td className="p-3">{item.event_type}</td>
                            <td className="p-3 text-right">
                              <button className="text-[10px] font-mono uppercase text-[#38bdf8] border border-[#38bdf8] px-2 py-0.5">
                                {selectedIncident?.id === item.id ? 'DETAILS' : 'VIEW'}
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* DETAIL PANEL */}
              {selectedIncident && (
                <div className="w-[360px] bg-[#1c1c1f] border border-[#27272a] flex flex-col shrink-0 overflow-hidden">
                  <div className="h-1 w-full bg-[#f43f5e]"></div>
                  <div className="p-4 border-b border-[#27272a]">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="bg-[rgba(244,63,94,0.1)] border border-[#f43f5e] text-[#f43f5e] px-2 py-0.5 font-mono text-[9px] uppercase">
                        Critical Drift
                      </span>
                      <span className="text-[#a1a1aa] font-mono text-[10px]">
                        {formatTimestamp(selectedIncident.timestamp)}
                      </span>
                    </div>
                    <h3 className="font-semibold text-white text-[14px] truncate mt-2">{selectedIncident.resource_id}</h3>
                    <p className="text-[10px] font-mono text-[#a1a1aa]">Event: {selectedIncident.event_type}</p>
                  </div>

                  <div className="flex-1 overflow-y-auto p-4 space-y-4 text-[12px]">
                    
                    {/* NEW: COMPLIANCE CONTEXT BLOCK */}
                    <div>
                      <h4 className="font-mono text-[10px] text-[#a1a1aa] uppercase mb-2 border-b border-[#27272a] pb-1">
                        Compliance Context ({activeFramework})
                      </h4>
                      <div className="bg-[#131315] p-3 border-l-2 border-[#38bdf8] rounded-r border-t border-r border-b border-[#27272a]">
                        <span className="text-[#38bdf8] text-[11px] font-bold block mb-1">
                          {frameworkConfig[activeFramework].label}
                        </span>
                        <span className="text-white font-mono text-[11px] block leading-relaxed">
                          {selectedIncident[frameworkConfig[activeFramework].db_key] 
                            ? selectedIncident[frameworkConfig[activeFramework].db_key] as string 
                            : 'No specific control mapped for this framework.'}
                        </span>
                      </div>

                      {/* The "Also Violates" Peek */}
                      <div className="mt-2 text-[10px] font-mono flex flex-wrap gap-1.5">
                        <span className="text-[#71717a] italic">Also violates:</span>
                        {(Object.keys(frameworkConfig) as FrameworkKey[])
                          .filter(fw => fw !== activeFramework && selectedIncident[frameworkConfig[fw].db_key])
                          .map((fw, index, array) => (
                            <span key={fw} className="text-[#a1a1aa]">
                              {fw}{index < array.length - 1 ? ',' : ''}
                            </span>
                          ))}
                        {(Object.keys(frameworkConfig) as FrameworkKey[]).filter(fw => fw !== activeFramework && selectedIncident[frameworkConfig[fw].db_key]).length === 0 && (
                          <span className="text-[#71717a]">None</span>
                        )}
                      </div>
                    </div>

                    <div>
                      <h4 className="font-mono text-[10px] text-[#a1a1aa] uppercase mb-1 border-b border-[#27272a] pb-1">Threat Context</h4>
                      <p className="text-white leading-relaxed">{getThreatContext(selectedIncident)}</p>
                    </div>

                    <div>
                      <h4 className="font-mono text-[10px] text-[#a1a1aa] uppercase mb-1 border-b border-[#27272a] pb-1">Configuration Diff</h4>
                      <pre className="bg-[#000000] p-3 text-[11px] font-mono text-[#38bdf8] whitespace-pre-wrap break-all border border-[#27272a]">
                        {formatDetails(selectedIncident.details)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ASSETS */}
          {activeTab === 'assets' && (
            <div className="w-full bg-[#131315] border border-[#27272a] flex flex-col overflow-hidden">
              <div className="p-5 border-b border-[#27272a]">
                <h3 className="text-[14px] font-bold text-white uppercase">Monitored Cloud Infrastructure</h3>
                <p className="text-[12px] text-[#a1a1aa] mt-1">Global inventory of AWS EC2, S3, IAM, and RDS assets.</p>
              </div>
              <div className="flex-1 overflow-y-auto">
                <table className="w-full text-left text-[12px]">
                  <thead className="bg-[#09090b] text-[#a1a1aa] uppercase font-mono text-[10px] sticky top-0 border-b border-[#27272a]">
                    <tr>
                      <th className="p-4">AWS Service</th>
                      <th className="p-4">Resource ID</th>
                      <th className="p-4 text-right">Posture Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#27272a]">
                    {incidents.length === 0 && metrics.monitored_assets === 0 ? (
                      <tr>
                        <td colSpan={3} className="p-8 text-center text-[#71717a] font-mono uppercase">None</td>
                      </tr>
                    ) : (
                      <>
                        {Array.from(new Set(incidents.map(i => i.resource_id))).map(resId => (
                          <tr key={resId} className="hover:bg-[#1c1c1f] transition-colors">
                            <td className="p-4 font-mono text-[#a1a1aa]">{getAssetClass(resId)}</td>
                            <td className="p-4 font-bold text-white">{resId}</td>
                            <td className="p-4 text-right">
                              <span className="text-[10px] font-mono bg-[rgba(244,63,94,0.1)] text-[#f43f5e] border border-[#f43f5e] px-2 py-1 uppercase">
                                Drift Detected : Security Risk
                              </span>
                            </td>
                          </tr>
                        ))}
                        
                        <tr className="hover:bg-[#1c1c1f] transition-colors">
                          <td className="p-4 font-mono text-[#a1a1aa]">S3 / Storage</td>
                          <td className="p-4 font-bold text-white">driftwatch-secure-audit-logs</td>
                          <td className="p-4 text-right">
                            <span className="text-[10px] font-mono bg-[rgba(56,189,248,0.1)] text-[#38bdf8] border border-[#38bdf8] px-2 py-1 uppercase">
                              Compliant and Safe
                            </span>
                          </td>
                        </tr>
                        <tr className="hover:bg-[#1c1c1f] transition-colors">
                          <td className="p-4 font-mono text-[#a1a1aa]">IAM / Identity</td>
                          <td className="p-4 font-bold text-white">arn:aws:iam::account:role/admin-baseline</td>
                          <td className="p-4 text-right">
                            <span className="text-[10px] font-mono bg-[rgba(56,189,248,0.1)] text-[#38bdf8] border border-[#38bdf8] px-2 py-1 uppercase">
                              Compliant and Safe
                            </span>
                          </td>
                        </tr>
                      </>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: FRAMEWORKS */}
          {activeTab === 'frameworks' && (
            <div className="w-full bg-[#131315] border border-[#27272a] flex flex-col overflow-hidden">
              <div className="p-5 border-b border-[#27272a] flex justify-between items-center bg-[#09090b]">
                <div>
                  <h3 className="text-[14px] font-bold text-white uppercase">Compliance Controls Framework</h3>
                  <p className="text-[12px] text-[#a1a1aa] mt-1">Rule definitions and technical triggers mapping.</p>
                </div>
                
                <div className="flex gap-2 bg-[#131315] p-1 border border-[#27272a]">
                  {['All', 'DPDPA', 'GDPR', 'CIS', 'ISO'].map(filter => (
                    <button
                      key={filter}
                      onClick={() => setFrameworkFilter(filter)}
                      className={`px-3 py-1 font-mono text-[10px] uppercase transition-colors ${
                        frameworkFilter === filter 
                          ? 'bg-[#27272a] text-[#38bdf8] border border-[#38bdf8]' 
                          : 'text-[#a1a1aa] border border-transparent hover:text-white'
                      }`}
                    >
                      {filter}
                    </button>
                  ))}
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-5 space-y-3">
                {frameworks
                  .filter(fw => frameworkFilter === 'All' || fw.framework === frameworkFilter)
                  .map(fw => (
                  <div key={fw.id} className="bg-[#09090b] border border-[#27272a] p-4 flex justify-between items-start text-[12px]">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-bold text-[#38bdf8] font-mono bg-[#1c1c1f] px-2 py-0.5 border border-[#27272a]">{fw.framework}</span>
                        <span className="text-white font-semibold font-mono">{fw.control_id}</span>
                      </div>
                      <p className="text-[#a1a1aa]">{fw.description}</p>
                      <p className="text-[10px] text-[#71717a] font-mono mt-2">Trigger: {fw.trigger_condition}</p>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-1 uppercase border ${
                      fw.risk_level === 'Critical' ? 'border-[#f43f5e] text-[#f43f5e] bg-[rgba(244,63,94,0.1)]' : 'border-[#38bdf8] text-[#38bdf8] bg-[rgba(56,189,248,0.1)]'
                    }`}>
                      {fw.risk_level}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 5: SETTINGS */}
          {activeTab === 'settings' && (
            <div className="w-full bg-[#131315] border border-[#27272a] p-6 overflow-y-auto">
              <h3 className="text-[14px] font-bold text-white uppercase mb-4">System Configuration</h3>
              <div className="space-y-4 text-[12px] max-w-md">
                <div className="bg-[#09090b] border border-[#27272a] p-4">
                  <p className="text-[#a1a1aa] font-mono text-[10px] uppercase">AWS Region Target</p>
                  <p className="text-white font-bold mt-1">us-east-1</p>
                </div>
                <div className="bg-[#09090b] border border-[#27272a] p-4">
                  <p className="text-[#a1a1aa] font-mono text-[10px] uppercase">Database Location</p>
                  <p className="text-white font-bold mt-1">backend/driftwatch.db (SQLite3)</p>
                </div>
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  )
}