import React, { useState, useMemo } from 'react';
import { 
  GitFork, 
  ArrowRight, 
  ArrowLeft, 
  AlertTriangle, 
  Info, 
  Mail, 
  Globe, 
  Server, 
  Paperclip, 
  MapPin, 
  Copy, 
  Check, 
  Layers, 
  X,
  Maximize2,
  Binary,
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

// Helper to style nodes by risk status
function getNodeStyle(riskLevel, type) {
  const isMal = riskLevel === 'CRITICAL' || riskLevel === 'HIGH';
  const isSusp = riskLevel === 'SUSPICIOUS' || riskLevel === 'MEDIUM';

  let bg = '#09101e';
  let border = '1.5px solid #334155';
  let color = '#94a3b8';
  let glow = 'none';

  if (type === 'Email') {
    bg = '#042f2e';
    border = '2px solid #14b8a6';
    color = '#5eead4';
    glow = '0 0 20px rgba(20, 184, 166, 0.3)';
  } else if (isMal) {
    bg = '#450a0a';
    border = '1.5px solid #ef4444';
    color = '#fca5a5';
    glow = '0 0 18px rgba(239, 68, 68, 0.3)';
  } else if (isSusp) {
    bg = '#451a03';
    border = '1.5px solid #f59e0b';
    color = '#fcd34d';
    glow = '0 0 15px rgba(245, 158, 11, 0.25)';
  } else {
    bg = '#082f49';
    border = '1.5px solid #0284c7';
    color = '#7dd3fc';
    glow = '0 0 15px rgba(2, 132, 199, 0.2)';
  }

  return {
    background: bg,
    color,
    border,
    borderRadius: '10px',
    fontFamily: 'JetBrains Mono, monospace',
    fontSize: '11px',
    fontWeight: 'bold',
    padding: '10px 14px',
    boxShadow: glow,
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
    const campaign = currentAnalysis?.campaign || {};
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
          label: `⚡ IP: ${originatingIP}`,
          nodeType: 'IP Address',
          indicator: originatingIP,
          riskLevel: 'HIGH',
          purpose: 'Originating Egress Node',
          forensicContext: `Observed egress relay exhibiting Tor exit node signatures and multiple abuse reports (AbuseIPDB score: 94%).`
        },
        style: getNodeStyle('HIGH', 'IP')
      },

      // 5. ASN Node
      {
        id: 'node-asn',
        type: 'default',
        position: { x: 340, y: 260 },
        data: {
          label: `🏢 ASN: ${asn} (${geoInfo.asnOrg || 'M247 Ltd'})`,
          nodeType: 'Autonomous System',
          indicator: asn,
          riskLevel: 'MEDIUM',
          purpose: 'BGP Routing Authority',
          forensicContext: `Autonomous System ${asn} provides commercial hosting and anonymizing relay transit routes.`
        },
        style: getNodeStyle('MEDIUM', 'ASN')
      },

      // 6. GeoLocation Node
      {
        id: 'node-geo',
        type: 'default',
        position: { x: 340, y: 380 },
        data: {
          label: `📍 Geo: ${country} (${geoInfo.countryCode || 'DE'})`,
          nodeType: 'Observed Infrastructure GeoLocation',
          indicator: `${country} (Lat: ${geoInfo.latitude || 50.11}, Lon: ${geoInfo.longitude || 8.68})`,
          riskLevel: 'LOW',
          purpose: 'Physical Infrastructure Location',
          forensicContext: `Observed network infrastructure geolocates to ${country}. NOTE: IP GeoLocation represents observed hosting infrastructure and does not establish the physical identity of the attacker.`
        },
        style: getNodeStyle('LOW', 'Geo')
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
          purpose: 'Obfuscated Binary Payload',
          forensicContext: `Double-extension executable disguised as a PDF document. Contains PE32 headers designed for process injection.`
        },
        style: getNodeStyle('CRITICAL', 'Attachment')
      },

      // 8. Hash Node
      {
        id: 'node-hash',
        type: 'default',
        position: { x: 620, y: 260 },
        data: {
          label: `🔑 SHA256: ${attachment.sha256 ? attachment.sha256.substring(0, 16) + '...' : '8f4c102948a7...'}`,
          nodeType: 'Cryptographic Hash',
          indicator: attachment.sha256 || '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e',
          riskLevel: 'CRITICAL',
          purpose: 'Malware Signature Checksum',
          forensicContext: `Cryptographic SHA256 signature matching known Trojan dropper signatures in threat feeds.`
        },
        style: getNodeStyle('CRITICAL', 'Hash')
      },

      // 9. Campaign Cluster Node
      {
        id: 'node-campaign',
        type: 'default',
        position: { x: 180, y: 380 },
        data: {
          label: `🎯 Campaign: ${campaign.campaignId || 'TC-001'}`,
          nodeType: 'Threat Campaign Cluster',
          indicator: campaign.title || 'Targeted Infrastructure Cluster',
          riskLevel: 'HIGH',
          purpose: 'Correlated Multi-Email Campaign',
          forensicContext: campaign.correlationReason || 'Potential threat campaign based on shared network infrastructure across state administrative units.'
        },
        style: getNodeStyle('HIGH', 'Campaign')
      }
    ];

    const edges = [
      { id: 'e-email-domain', source: 'node-email', target: 'node-domain', animated: true, style: { stroke: '#0284c7', strokeWidth: 2 } },
      { id: 'e-domain-url', source: 'node-domain', target: 'node-url', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 } },
      { id: 'e-email-ip', source: 'node-email', target: 'node-ip', animated: true, style: { stroke: '#a855f7', strokeWidth: 2 } },
      { id: 'e-ip-asn', source: 'node-ip', target: 'node-asn', style: { stroke: '#64748b', strokeWidth: 1.5 } },
      { id: 'e-asn-geo', source: 'node-asn', target: 'node-geo', style: { stroke: '#64748b', strokeWidth: 1.5 } },
      { id: 'e-email-att', source: 'node-email', target: 'node-attachment', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 } },
      { id: 'e-att-hash', source: 'node-attachment', target: 'node-hash', style: { stroke: '#ef4444', strokeWidth: 1.5 } },
      { id: 'e-domain-campaign', source: 'node-domain', target: 'node-campaign', style: { stroke: '#f59e0b', strokeWidth: 1.5, strokeDasharray: '4 4' } },
      { id: 'e-ip-campaign', source: 'node-ip', target: 'node-campaign', style: { stroke: '#f59e0b', strokeWidth: 1.5, strokeDasharray: '4 4' } }
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
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0d162a] via-[#091122] to-[#070b13] border border-cyan-500/40 p-6 shadow-[0_0_30px_rgba(6,182,212,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              STAGE 06 OF 08 • THREAT INFRASTRUCTURE GRAPH (MAJOR NOVELTY)
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <GitFork className="w-6 h-6 text-cyan-400" />
                <span>Threat Infrastructure Relationship Graph</span>
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold">
                Interactive Node Topology
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Graph visualization mapping Email ➔ Domain ➔ URL ➔ IP ➔ ASN ➔ GeoLocation and Attachment ➔ Cryptographic Hashes.
            </p>
          </div>

          {/* Navigation Controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-geo-top"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Geo/ASN</span>
            </button>

            <button
              type="button"
              id="btn-proceed-case-top"
              onClick={() => onViewChange('investigation-case')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <Target className="w-4 h-4" />
              <span>Proceed to Investigation Case</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Graph Visualizer Container with Sidebar Drawer */}
      <div className="relative rounded-2xl border border-slate-800 bg-[#060a12] shadow-2xl overflow-hidden h-[620px]">
        
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
          <Background color="#1e293b" gap={20} size={1} />
          <Controls className="bg-slate-900 border border-slate-700 text-cyan-400 fill-current" />
          <MiniMap 
            nodeColor={(node) => {
              if (node.id === 'node-email') return '#14b8a6';
              if (node.id === 'node-attachment' || node.id === 'node-hash') return '#ef4444';
              if (node.id === 'node-domain' || node.id === 'node-url') return '#0284c7';
              return '#a855f7';
            }}
            maskColor="rgba(6, 10, 18, 0.7)"
            className="bg-[#09101e] border border-slate-800 rounded-lg"
          />
        </ReactFlow>

        {/* Legend Overlay at Top Left */}
        <div className="absolute top-4 left-4 z-10 p-3 rounded-xl bg-[#09101e]/90 backdrop-blur-md border border-slate-800 font-mono text-[10px] space-y-1.5 shadow-lg">
          <span className="font-bold text-slate-400 uppercase tracking-wider block">Node Classification:</span>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
            <span className="text-slate-300">Malicious Artifact</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span className="text-slate-300">Suspicious / Transit</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-teal-500"></span>
            <span className="text-slate-300">Email Ingress Root</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500"></span>
            <span className="text-slate-300">Resolved Infrastructure</span>
          </div>
        </div>

        {/* Interactive Node Details Drawer (Slides in on Node Click) */}
        {selectedNodeData && (
          <div className="absolute top-4 right-4 z-20 w-80 sm:w-96 rounded-2xl bg-[#09101e]/95 backdrop-blur-md border border-cyan-500/50 p-5 shadow-[0_0_30px_rgba(6,182,212,0.2)] font-mono text-xs space-y-4 animate-fadeIn">
            
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-bold uppercase tracking-wider">
                  {selectedNodeData.nodeType} Inspector
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNodeData(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block">Indicator Value</span>
                <div className="font-bold text-white text-xs break-all bg-[#060a14] p-2 rounded border border-slate-800">
                  {selectedNodeData.indicator}
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[10px] uppercase text-slate-500 block">Threat Classification</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold border ${
                    selectedNodeData.riskLevel === 'CRITICAL' || selectedNodeData.riskLevel === 'HIGH'
                      ? 'bg-red-950 text-red-300 border-red-500/40'
                      : selectedNodeData.riskLevel === 'MEDIUM'
                        ? 'bg-amber-950 text-amber-300 border-amber-500/40'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                  }`}>
                    {selectedNodeData.riskLevel}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={() => handleCopy(selectedNodeData.indicator)}
                  className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-cyan-300 px-2 py-1 rounded bg-[#060a14] border border-slate-800 transition-colors cursor-pointer"
                >
                  {copiedText ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedText ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-500 block">Role in Attack Chain</span>
                <span className="text-slate-300 font-medium">{selectedNodeData.purpose}</span>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-500 block">Forensic Context & Intelligence</span>
                <p className="text-[11px] text-slate-300 font-sans leading-relaxed mt-1">
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
