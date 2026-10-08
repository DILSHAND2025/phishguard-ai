import React, { useState, useMemo } from 'react';
import { 
  GitFork, 
  ArrowRight, 
  ArrowLeft, 
  Copy, 
  Check, 
  X,
  Target
} from 'lucide-react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap, 
  useNodesState, 
  useEdgesState 
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// Helper to style nodes by risk status (clean light theme)
function getNodeStyle(riskLevel, type) {
  const isMal = riskLevel === 'CRITICAL' || riskLevel === 'HIGH';
  const isSusp = riskLevel === 'SUSPICIOUS' || riskLevel === 'MEDIUM';

  let bg = '#ffffff';
  let border = '1.5px solid #cbd5e1';
  let color = '#334155';

  if (type === 'Email') {
    bg = '#f8fafc';
    border = '2px solid #0f172a';
    color = '#0f172a';
  } else if (isMal) {
    bg = '#fef2f2';
    border = '1.5px solid #fca5a5';
    color = '#991b1b';
  } else if (isSusp) {
    bg = '#fffbeb';
    border = '1.5px solid #fde68a';
    color = '#92400e';
  } else {
    bg = '#f0f9ff';
    border = '1.5px solid #bae6fd';
    color = '#0369a1';
  }

  return {
    background: bg,
    color,
    border,
    borderRadius: '10px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontSize: '11px',
    fontWeight: '600',
    padding: '10px 14px',
    boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
    cursor: 'pointer'
  };
}

export const ThreatGraphPage = ({ onViewChange, currentAnalysis }) => {
  const [selectedNodeData, setSelectedNodeData] = useState(null);
  const [copiedText, setCopiedText] = useState(false);

  // Generate dynamic nodes and edges based on active analysis
  const { initialNodes, initialEdges } = useMemo(() => {
    const email = currentAnalysis?.email || {};
    const geoInfo = currentAnalysis?.geoInfo || {};
    const iocs = currentAnalysis?.iocs || [];
    const fusion = currentAnalysis?.fusion || {};

    const subject = email.subject || 'Suspicious BEC Wire Directive';
    const domain = email.fromParsed?.domain || 'internal-corp-portal.online';
    const originatingIP = email.originatingIP || geoInfo.ip || '185.220.101.45';
    const asn = geoInfo.asn || 'AS9009';
    const country = geoInfo.country || 'Germany';
    const attachment = email.attachments?.[0] || { filename: 'Wire_Remittance_Directive.pdf.exe', sha256: '8f4c102948a7b6c5d4e3f27d1a293b6e...' };
    const url = iocs.find(i => i.type === 'URL')?.value || 'http://internal-corp-portal.online/auth-portal/wire-release';

    const nodes = [
      // 1. Email Root Node
      {
        id: 'node-email',
        type: 'default',
        position: { x: 340, y: 20 },
        data: {
          label: `✉️ Email: ${subject.length > 28 ? subject.substring(0, 25) + '...' : subject}`,
          nodeType: 'Email',
          indicator: subject,
          riskLevel: fusion.riskLevel || 'HIGH',
          purpose: 'Initial Phishing Ingestion Vector',
          forensicContext: `Ingested RFC 822 envelope targeting ${email.recipient || 'treasury-controller@gov-organization.in'}. SPF/DKIM authentication failures and coercive language detected.`
        },
        style: getNodeStyle(fusion.riskLevel || 'HIGH', 'Email')
      },

      // 2. Domain Node
      {
        id: 'node-domain',
        type: 'default',
        position: { x: 140, y: 140 },
        data: {
          label: `🌐 Domain: ${domain}`,
          nodeType: 'Domain',
          indicator: domain,
          riskLevel: 'HIGH',
          purpose: 'Lookalike / Typosquatting Infrastructure',
          forensicContext: `Domain registered recently mimicking internal organization portal. Lacks authentic historical MX records.`
        },
        style: getNodeStyle('HIGH', 'Domain')
      },

      // 3. URL Node
      {
        id: 'node-url',
        type: 'default',
        position: { x: 40, y: 260 },
        data: {
          label: `🔗 URL: ${url.length > 25 ? url.substring(0, 22) + '...' : url}`,
          nodeType: 'URL',
          indicator: url,
          riskLevel: 'HIGH',
          purpose: 'Credential Phishing Endpoint',
          forensicContext: `Embedded hyperlink configured to harvest SSO authorization tokens and wire approval signatures.`
        },
        style: getNodeStyle('HIGH', 'URL')
      },

      // 4. IP Node
      {
        id: 'node-ip',
        type: 'default',
        position: { x: 400, y: 140 },
        data: {
          label: `🖥️ Origin IP: ${originatingIP}`,
          nodeType: 'IP',
          indicator: originatingIP,
          riskLevel: 'CRITICAL',
          purpose: 'Egress Routing Infrastructure',
          forensicContext: `Network origin IP recorded in earliest Received header hop. Flagged for anonymizing transit proxy.`
        },
        style: getNodeStyle('CRITICAL', 'IP')
      },

      // 5. ASN Node
      {
        id: 'node-asn',
        type: 'default',
        position: { x: 300, y: 260 },
        data: {
          label: `🏢 ASN: ${asn} (M247)`,
          nodeType: 'ASN',
          indicator: asn,
          riskLevel: 'MEDIUM',
          purpose: 'Autonomous System Transit Provider',
          forensicContext: `Hosting and transit autonomous network organization operating anonymizing Tor egress hops.`
        },
        style: getNodeStyle('MEDIUM', 'ASN')
      },

      // 6. GeoLocation Node
      {
        id: 'node-geo',
        type: 'default',
        position: { x: 470, y: 260 },
        data: {
          label: `📍 Geo: ${country}`,
          nodeType: 'GeoLocation',
          indicator: country,
          riskLevel: 'LOW',
          purpose: 'Physical Routing Location',
          forensicContext: `Infrastructure location resolved via BGP table telemetry. (Reflects egress server location, not confirmed threat actor citizenship).`
        },
        style: getNodeStyle('LOW', 'GeoLocation')
      },

      // 7. Attachment Node
      {
        id: 'node-attachment',
        type: 'default',
        position: { x: 620, y: 140 },
        data: {
          label: `📎 Attachment: ${attachment.filename}`,
          nodeType: 'Attachment',
          indicator: attachment.filename,
          riskLevel: 'CRITICAL',
          purpose: 'Malicious Executable Dropper',
          forensicContext: `Double extension (.pdf.exe) obfuscating PE32 binary payload. Static header analysis confirms executable byte signature.`
        },
        style: getNodeStyle('CRITICAL', 'Attachment')
      },

      // 8. Hash Node
      {
        id: 'node-hash',
        type: 'default',
        position: { x: 640, y: 260 },
        data: {
          label: `#️⃣ SHA256: ${attachment.sha256?.substring(0, 12)}...`,
          nodeType: 'Hash',
          indicator: attachment.sha256 || '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e',
          riskLevel: 'CRITICAL',
          purpose: 'Cryptographic Artifact Fingerprint',
          forensicContext: `Immutable SHA-256 fingerprint verified through static binary hashing. Matches malware repository dropper signatures.`
        },
        style: getNodeStyle('CRITICAL', 'Hash')
      }
    ];

    const edges = [
      { id: 'e-email-domain', source: 'node-email', target: 'node-domain', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
      { id: 'e-domain-url', source: 'node-domain', target: 'node-url', style: { stroke: '#ef4444', strokeWidth: 1.5 } },
      { id: 'e-email-ip', source: 'node-email', target: 'node-ip', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
      { id: 'e-ip-asn', source: 'node-ip', target: 'node-asn', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
      { id: 'e-ip-geo', source: 'node-ip', target: 'node-geo', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
      { id: 'e-email-att', source: 'node-email', target: 'node-attachment', style: { stroke: '#ef4444', strokeWidth: 1.5 } },
      { id: 'e-att-hash', source: 'node-attachment', target: 'node-hash', style: { stroke: '#ef4444', strokeWidth: 1.5 } }
    ];

    return { initialNodes: nodes, initialEdges: edges };
  }, [currentAnalysis]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync state if currentAnalysis updates
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const onNodeClick = (_, node) => {
    setSelectedNodeData(node.data);
  };

  const handleCopy = (text) => {
    navigator.clipboard?.writeText(text);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 1500);
  };

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-900">
      
      {/* Top Banner Header */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1.5">
              <span>Threat Infrastructure Graph</span>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 flex items-center gap-2.5">
                <GitFork className="w-6 h-6 text-slate-700" />
                <span>Relationship Graph</span>
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold">
                Interactive Topology
              </span>
            </div>

            <p className="text-xs text-slate-500 mt-1.5">
              Graph visualization mapping Email ➔ Domain ➔ URL ➔ IP ➔ ASN ➔ GeoLocation and Attachment ➔ Hashes.
            </p>
          </div>

          {/* Navigation Controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-geo-top"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-slate-500" />
              <span>Back to Geo/ASN</span>
            </button>

            <button
              type="button"
              id="btn-proceed-case-top"
              onClick={() => onViewChange('cases')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Target className="w-4 h-4" />
              <span>Proceed to Cases</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Graph Visualizer Container with Sidebar Drawer */}
      <div className="relative rounded-xl border border-slate-200 bg-slate-50 shadow-xs overflow-hidden h-[620px]">
        
        {/* React Flow Viewport */}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.5}
          maxZoom={1.8}
        >
          <Background color="#cbd5e1" gap={20} size={1} />
          <Controls className="bg-white border border-slate-200 text-slate-700 shadow-xs" />
          <MiniMap 
            nodeColor={(node) => {
              if (node.id === 'node-email') return '#0f172a';
              if (node.id === 'node-attachment' || node.id === 'node-hash') return '#ef4444';
              if (node.id === 'node-domain' || node.id === 'node-url') return '#0284c7';
              return '#a855f7';
            }}
            maskColor="rgba(241, 245, 249, 0.7)"
            className="bg-white border border-slate-200 rounded-lg shadow-2xs"
          />
        </ReactFlow>

        {/* Legend Overlay at Top Left */}
        <div className="absolute top-4 left-4 z-10 p-3 rounded-xl bg-white/95 backdrop-blur-xs border border-slate-200 text-xs space-y-1.5 shadow-sm">
          <span className="font-bold text-slate-600 uppercase tracking-wider block text-[10px]">Classification:</span>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
            <span className="text-slate-700 font-medium">Malicious Artifact</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span className="text-slate-700 font-medium">Suspicious Indicator</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-800"></span>
            <span className="text-slate-700 font-medium">Ingress Origin</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-500"></span>
            <span className="text-slate-700 font-medium">Network Node</span>
          </div>
        </div>

        {/* Interactive Node Details Drawer (Slides in on Node Click) */}
        {selectedNodeData && (
          <div className="absolute top-4 right-4 z-20 w-80 sm:w-96 rounded-xl bg-white/95 backdrop-blur-xs border border-slate-300 p-5 shadow-lg text-xs space-y-4">
            
            <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
              <div className="flex items-center gap-2">
                <span className="text-slate-900 font-bold uppercase tracking-wider">
                  {selectedNodeData.nodeType} Inspector
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNodeData(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-semibold">Indicator Value</span>
                <div className="font-bold text-slate-900 text-xs break-all bg-slate-50 p-2.5 rounded-lg border border-slate-200 mt-1 font-mono">
                  {selectedNodeData.indicator}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[10px] uppercase text-slate-500 block font-semibold">Classification</span>
                  <span className={`inline-block mt-0.5 px-2.5 py-0.5 rounded text-[10px] font-bold border ${
                    selectedNodeData.riskLevel === 'CRITICAL' || selectedNodeData.riskLevel === 'HIGH'
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : selectedNodeData.riskLevel === 'MEDIUM'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {selectedNodeData.riskLevel}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopy(selectedNodeData.indicator)}
                  className="flex items-center gap-1 text-[11px] text-slate-600 hover:text-slate-900 px-2 py-1 rounded bg-slate-50 border border-slate-200 transition-colors cursor-pointer font-medium"
                >
                  {copiedText ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                  <span>{copiedText ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-semibold">Role in Attack Chain</span>
                <span className="text-slate-800 font-medium block mt-0.5">{selectedNodeData.purpose}</span>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-semibold">Forensic Context</span>
                <p className="text-xs text-slate-600 leading-relaxed mt-1">
                  {selectedNodeData.forensicContext}
                </p>
              </div>
            </div>

          </div>
        )}

      </div>

    </div>
  );
};
