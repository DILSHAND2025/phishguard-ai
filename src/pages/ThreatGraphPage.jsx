import React, { useState } from 'react';
import { 
  GitFork, 
  ArrowRight, 
  ArrowLeft, 
  AlertTriangle, 
  Info, 
  Mail, 
  Globe, 
  Globe2, 
  Server, 
  Paperclip, 
  Radio, 
  MapPin, 
  Building, 
  Copy, 
  Check, 
  Layers, 
  X,
  Maximize2
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

const initialNodes = [
  // 1. Email Root Node
  {
    id: 'node-email',
    type: 'default',
    position: { x: 300, y: 20 },
    data: { 
      label: '✉️ Email: Suspicious Email',
      nodeType: 'Email',
      indicator: 'Suspicious Email',
      riskLevel: 'HIGH',
      purpose: 'Initial Ingestion Vector',
      forensicContext: 'Synthetic email sample containing embedded phishing hyperlinks, suspicious routing headers, and an obfuscated executable attachment.'
    },
    style: {
      background: '#042f2e',
      color: '#5eead4',
      border: '2px solid #14b8a6',
      borderRadius: '10px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '10px 14px',
      boxShadow: '0 0 20px rgba(20, 184, 166, 0.3)'
    },
  },

  // 2. Attachment Node (connected from Email)
  {
    id: 'node-attachment',
    type: 'default',
    position: { x: 50, y: 130 },
    data: { 
      label: '📎 Attachment: invoice.pdf',
      nodeType: 'Attachment',
      indicator: 'invoice.pdf',
      riskLevel: 'HIGH',
      purpose: 'Suspicious attachment',
      forensicContext: 'Simulated double-extension attachment payload (invoice.pdf.exe) flagged for executable header signatures.'
    },
    style: {
      background: '#450a0a',
      color: '#fca5a5',
      border: '1.5px solid #ef4444',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px',
      boxShadow: '0 0 15px rgba(239, 68, 68, 0.25)'
    },
  },

  // 3. Domain Node (connected from Email)
  {
    id: 'node-domain',
    type: 'default',
    position: { x: 340, y: 130 },
    data: { 
      label: '🌐 Domain: bad-update.net',
      nodeType: 'Domain',
      indicator: 'bad-update.net',
      riskLevel: 'HIGH',
      purpose: 'Malicious domain indicator',
      forensicContext: 'Deceptive lookalike domain exhibiting high entropy and synthetic registration characteristics targeting enterprise software updates.'
    },
    style: {
      background: '#082f49',
      color: '#7dd3fc',
      border: '1.5px solid #0284c7',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px',
      boxShadow: '0 0 15px rgba(2, 132, 199, 0.25)'
    },
  },

  // 4. URL Node (connected from Domain)
  {
    id: 'node-url',
    type: 'default',
    position: { x: 130, y: 240 },
    data: { 
      label: '🔗 URL: malicious-site.com/login',
      nodeType: 'URL',
      indicator: 'malicious-site.com/login',
      riskLevel: 'HIGH',
      purpose: 'Credential phishing',
      forensicContext: 'Extracted hyperlink redirecting users to a simulated credential harvester designed to replicate corporate single sign-on portals.'
    },
    style: {
      background: '#451a03',
      color: '#fdba74',
      border: '1.5px solid #f97316',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px',
      boxShadow: '0 0 15px rgba(249, 115, 22, 0.25)'
    },
  },

  // 5. IP 1 Node (connected from Domain)
  {
    id: 'node-ip-1',
    type: 'default',
    position: { x: 350, y: 240 },
    data: { 
      label: '⚡ IP: 185.220.101.15',
      nodeType: 'IP',
      indicator: '185.220.101.15',
      riskLevel: 'HIGH',
      purpose: 'Suspicious infrastructure',
      forensicContext: 'Simulated relay and origin egress IP address associated with anonymized hosting nodes.'
    },
    style: {
      background: '#3b0764',
      color: '#d8b4fe',
      border: '1.5px solid #a855f7',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px',
      boxShadow: '0 0 15px rgba(168, 85, 247, 0.25)'
    },
  },

  // 6. IP 2 Node (connected from Domain)
  {
    id: 'node-ip-2',
    type: 'default',
    position: { x: 570, y: 240 },
    data: { 
      label: '⚡ IP: 104.21.36.45',
      nodeType: 'IP',
      indicator: '104.21.36.45',
      riskLevel: 'MEDIUM',
      purpose: 'Suspicious hosting infrastructure',
      forensicContext: 'Simulated edge hosting address providing frontend reverse proxy routing.'
    },
    style: {
      background: '#3b0764',
      color: '#d8b4fe',
      border: '1.5px solid #c084fc',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px',
      boxShadow: '0 0 15px rgba(192, 132, 252, 0.25)'
    },
  },

  // 7. ASN 1 Node (connected from IP 1)
  {
    id: 'node-asn-1',
    type: 'default',
    position: { x: 340, y: 350 },
    data: { 
      label: '📡 ASN: AS9009',
      nodeType: 'ASN',
      indicator: 'AS9009',
      riskLevel: 'HIGH',
      purpose: 'Autonomous System BGP Routing',
      forensicContext: 'Identifies the European network/organization prefix associated with the IP infrastructure.'
    },
    style: {
      background: '#1e1b4b',
      color: '#c7d2fe',
      border: '1.5px solid #6366f1',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  },

  // 8. ASN 2 Node (connected from IP 2)
  {
    id: 'node-asn-2',
    type: 'default',
    position: { x: 560, y: 350 },
    data: { 
      label: '📡 ASN: AS13335',
      nodeType: 'ASN',
      indicator: 'AS13335',
      riskLevel: 'MEDIUM',
      purpose: 'Autonomous System BGP Routing',
      forensicContext: 'Identifies the global cloud edge network prefix associated with the hosting IP infrastructure.'
    },
    style: {
      background: '#1e1b4b',
      color: '#c7d2fe',
      border: '1.5px solid #6366f1',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  },

  // 9. GeoLocation 1 Node (connected from ASN 1)
  {
    id: 'node-geo-1',
    type: 'default',
    position: { x: 320, y: 460 },
    data: { 
      label: '🌍 GeoLocation: Germany [DE]',
      nodeType: 'GeoLocation',
      indicator: 'Germany [DE]',
      riskLevel: 'HIGH',
      purpose: 'Approximate Hosting Facility Location',
      forensicContext: 'Indicates the geographic server datacenter region. Does not identify the physical location or identity of an attacker.'
    },
    style: {
      background: '#064e3b',
      color: '#a7f3d0',
      border: '1.5px solid #10b981',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  },

  // 10. GeoLocation 2 Node (connected from ASN 2)
  {
    id: 'node-geo-2',
    type: 'default',
    position: { x: 540, y: 460 },
    data: { 
      label: '🌍 GeoLocation: United States [US]',
      nodeType: 'GeoLocation',
      indicator: 'United States [US]',
      riskLevel: 'MEDIUM',
      purpose: 'Approximate Hosting Facility Location',
      forensicContext: 'Indicates the geographic edge transit region. Does not identify the physical location or identity of an attacker.'
    },
    style: {
      background: '#064e3b',
      color: '#a7f3d0',
      border: '1.5px solid #10b981',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  },

  // 11. Infrastructure Context 1 (connected from GeoLocation 1)
  {
    id: 'node-ctx-1',
    type: 'default',
    position: { x: 280, y: 560 },
    data: { 
      label: '🏢 Context: Hosting / relay infrastructure',
      nodeType: 'Infrastructure Context',
      indicator: 'Hosting / relay infrastructure',
      riskLevel: 'HIGH',
      purpose: 'Relay & Egress Classification',
      forensicContext: 'Characterized as high-risk anonymized proxy and relay nodes utilized in simulated email transit.'
    },
    style: {
      background: '#18181b',
      color: '#f4f4f5',
      border: '1.5px solid #ef4444',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  },

  // 12. Infrastructure Context 2 (connected from GeoLocation 2)
  {
    id: 'node-ctx-2',
    type: 'default',
    position: { x: 510, y: 560 },
    data: { 
      label: '🏢 Context: Hosting infrastructure',
      nodeType: 'Infrastructure Context',
      indicator: 'Hosting infrastructure',
      riskLevel: 'MEDIUM',
      purpose: 'Edge Transit Classification',
      forensicContext: 'Characterized as public edge reverse proxy infrastructure serving secondary web redirection.'
    },
    style: {
      background: '#18181b',
      color: '#f4f4f5',
      border: '1.5px solid #f59e0b',
      borderRadius: '8px',
      fontFamily: 'JetBrains Mono',
      fontSize: '11px',
      fontWeight: 'bold',
      padding: '9px 12px'
    },
  }
];

const initialEdges = [
  // Email -> Attachment
  { 
    id: 'edge-email-att', 
    source: 'node-email', 
    target: 'node-attachment', 
    animated: true, 
    label: 'contains attachment',
    style: { stroke: '#ef4444', strokeWidth: 2 },
    labelStyle: { fill: '#fca5a5', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // Email -> Domain
  { 
    id: 'edge-email-dom', 
    source: 'node-email', 
    target: 'node-domain', 
    animated: true, 
    label: 'from / sender domain',
    style: { stroke: '#06b6d4', strokeWidth: 2 },
    labelStyle: { fill: '#67e8f9', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // Domain -> URL
  { 
    id: 'edge-dom-url', 
    source: 'node-domain', 
    target: 'node-url', 
    animated: true, 
    label: 'hosts link',
    style: { stroke: '#f97316', strokeWidth: 2 },
    labelStyle: { fill: '#fdba74', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // Domain -> IP 1
  { 
    id: 'edge-dom-ip1', 
    source: 'node-domain', 
    target: 'node-ip-1', 
    animated: true, 
    label: 'resolves to',
    style: { stroke: '#a855f7', strokeWidth: 2 },
    labelStyle: { fill: '#d8b4fe', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // Domain -> IP 2
  { 
    id: 'edge-dom-ip2', 
    source: 'node-domain', 
    target: 'node-ip-2', 
    animated: true, 
    label: 'resolves to',
    style: { stroke: '#c084fc', strokeWidth: 2 },
    labelStyle: { fill: '#e9d5ff', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // IP 1 -> ASN 1
  { 
    id: 'edge-ip1-asn1', 
    source: 'node-ip-1', 
    target: 'node-asn-1', 
    animated: true, 
    label: 'allocated by',
    style: { stroke: '#6366f1', strokeWidth: 2 },
    labelStyle: { fill: '#c7d2fe', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // IP 2 -> ASN 2
  { 
    id: 'edge-ip2-asn2', 
    source: 'node-ip-2', 
    target: 'node-asn-2', 
    animated: true, 
    label: 'allocated by',
    style: { stroke: '#6366f1', strokeWidth: 2 },
    labelStyle: { fill: '#c7d2fe', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // ASN 1 -> GeoLocation 1
  { 
    id: 'edge-asn1-geo1', 
    source: 'node-asn-1', 
    target: 'node-geo-1', 
    animated: true, 
    label: 'datacenter facility',
    style: { stroke: '#10b981', strokeWidth: 2 },
    labelStyle: { fill: '#a7f3d0', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // ASN 2 -> GeoLocation 2
  { 
    id: 'edge-asn2-geo2', 
    source: 'node-asn-2', 
    target: 'node-geo-2', 
    animated: true, 
    label: 'edge node region',
    style: { stroke: '#10b981', strokeWidth: 2 },
    labelStyle: { fill: '#a7f3d0', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // GeoLocation 1 -> Context 1
  { 
    id: 'edge-geo1-ctx1', 
    source: 'node-geo-1', 
    target: 'node-ctx-1', 
    animated: true, 
    label: 'infrastructure role',
    style: { stroke: '#ef4444', strokeWidth: 2 },
    labelStyle: { fill: '#fca5a5', fontSize: 10, fontFamily: 'JetBrains Mono' }
  },
  // GeoLocation 2 -> Context 2
  { 
    id: 'edge-geo2-ctx2', 
    source: 'node-geo-2', 
    target: 'node-ctx-2', 
    animated: true, 
    label: 'infrastructure role',
    style: { stroke: '#f59e0b', strokeWidth: 2 },
    labelStyle: { fill: '#fde68a', fontSize: 10, fontFamily: 'JetBrains Mono' }
  }
];

export const ThreatGraphPage = ({ onViewChange }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  
  // Requirement 7: Node-click interaction state
  const [selectedNode, setSelectedNode] = useState(initialNodes[0].data);
  const [copiedIndicator, setCopiedIndicator] = useState(false);

  const handleNodeClick = (event, node) => {
    if (node && node.data) {
      setSelectedNode(node.data);
    }
  };

  const handleCopyIndicator = (text) => {
    if (text) {
      navigator.clipboard?.writeText(text);
      setCopiedIndicator(true);
      setTimeout(() => setCopiedIndicator(false), 1500);
    }
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-cyan-950/40 via-[#0d162a] to-[#070b13] border border-cyan-500/40 p-6 shadow-[0_0_30px_rgba(6,182,212,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              STAGE 06 OF 08 • THREAT INFRASTRUCTURE GRAPH (REACT FLOW)
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <GitFork className="w-6 h-6 text-cyan-400" />
                <span>Threat Infrastructure Graph</span>
              </h1>

              {/* Requirement 1: Clear badge SIMULATED DEMO DATA */}
              <span className="px-2.5 py-0.5 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 font-mono text-[11px] font-bold shadow-sm">
                SIMULATED DEMO DATA
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Multi-entity visual correlation: Email → Domain → URL/IP → ASN → GeoLocation → Attachment.
            </p>
          </div>

          {/* Top Navigation Actions */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {/* Requirement 10: Back to GeoLocation & ASN */}
            <button
              type="button"
              id="btn-back-geo-asn"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to GeoLocation & ASN</span>
            </button>

            {/* Requirement 10: Proceed to Investigation Case */}
            <button
              type="button"
              id="btn-proceed-investigation-case"
              onClick={() => onViewChange('investigation-case')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <span>Proceed to Investigation Case</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Requirement 2: Disclaimer near the graph */}
      <div className="rounded-xl bg-amber-950/30 border border-amber-500/40 p-4 font-mono text-xs text-amber-200 flex items-start gap-3 shadow-md">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold text-amber-300 block mb-0.5 uppercase tracking-wide">
            Forensic Scope Disclaimer:
          </span>
          <p className="text-amber-100/90 text-xs leading-relaxed font-sans">
            Graph models infrastructure correlation for SIH 2026 demonstration; it does not identify attacker identities.
          </p>
        </div>
      </div>

      {/* Main Graph & Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Left 3 Columns: React Flow Interactive Graph Canvas */}
        <div className="lg:col-span-3 rounded-xl bg-[#080d1a] border border-cyan-500/30 shadow-2xl overflow-hidden h-[620px] relative">
          
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            fitView
            className="bg-[#050811]"
          >
            <Background color="#1e293b" gap={16} size={1} />
            <Controls className="bg-[#091122] border-slate-800 text-slate-300" />
            <MiniMap 
              className="bg-[#091122] border border-slate-800 rounded-lg overflow-hidden" 
              nodeColor={(n) => {
                if (n.data?.nodeType === 'Email') return '#14b8a6';
                if (n.data?.nodeType === 'Attachment') return '#ef4444';
                if (n.data?.nodeType === 'Domain') return '#0284c7';
                if (n.data?.nodeType === 'URL') return '#f97316';
                if (n.data?.nodeType === 'IP') return '#a855f7';
                if (n.data?.nodeType === 'ASN') return '#6366f1';
                if (n.data?.nodeType === 'GeoLocation') return '#10b981';
                return '#64748b';
              }}
            />
          </ReactFlow>

          {/* Canvas Floating Quick Legend */}
          <div className="absolute bottom-4 left-4 p-3 rounded-lg bg-[#091224]/90 border border-slate-800 backdrop-blur-md text-[10px] font-mono space-y-1.5 pointer-events-none hidden sm:block">
            <div className="text-slate-400 font-bold uppercase text-[9px] mb-1">
              Infrastructure Categories
            </div>
            <div className="flex items-center gap-2 text-teal-300">
              <span className="w-2 h-2 rounded-full bg-teal-400"></span> Email (Ingestion Root)
            </div>
            <div className="flex items-center gap-2 text-red-300">
              <span className="w-2 h-2 rounded-full bg-red-400"></span> Attachment (Payload)
            </div>
            <div className="flex items-center gap-2 text-sky-300">
              <span className="w-2 h-2 rounded-full bg-sky-400"></span> Domain (Hosting Root)
            </div>
            <div className="flex items-center gap-2 text-orange-300">
              <span className="w-2 h-2 rounded-full bg-orange-400"></span> URL (Credential Vector)
            </div>
            <div className="flex items-center gap-2 text-purple-300">
              <span className="w-2 h-2 rounded-full bg-purple-400"></span> IP (Network Egress)
            </div>
            <div className="flex items-center gap-2 text-indigo-300">
              <span className="w-2 h-2 rounded-full bg-indigo-400"></span> ASN (Routing Entity)
            </div>
            <div className="flex items-center gap-2 text-emerald-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span> GeoLocation (Datacenter)
            </div>
          </div>
        </div>

        {/* Right 1 Column: Requirement 7 Side Inspector Panel */}
        <div className="lg:col-span-1 rounded-xl bg-[#09101e] border border-cyan-500/40 p-5 shadow-xl flex flex-col justify-between space-y-4 font-mono text-xs">
          
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold uppercase tracking-wider text-white text-xs">
                  Node Inspector
                </h3>
              </div>
              <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                Live Selection
              </span>
            </div>

            {selectedNode ? (
              <div className="space-y-3.5">
                
                {/* Node Type */}
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">
                    Node Type
                  </span>
                  <div className="text-white font-bold text-sm flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                    <span>{selectedNode.nodeType}</span>
                  </div>
                </div>

                {/* Indicator */}
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold">
                      Indicator
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyIndicator(selectedNode.indicator)}
                      className="text-slate-400 hover:text-cyan-300 text-[10px] flex items-center gap-1"
                      title="Copy Indicator"
                    >
                      {copiedIndicator ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedIndicator ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="text-cyan-300 font-bold break-all">
                    {selectedNode.indicator}
                  </div>
                </div>

                {/* Risk Level */}
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">
                    Risk Level
                  </span>
                  <div>
                    {selectedNode.riskLevel === 'HIGH' ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-red-950 border border-red-500/50 text-red-300 font-extrabold text-xs">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
                        <span>HIGH</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-amber-950 border border-amber-500/50 text-amber-300 font-bold text-xs">
                        <span>MEDIUM</span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Purpose */}
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">
                    Purpose
                  </span>
                  <div className="text-slate-200 font-sans text-xs font-medium">
                    {selectedNode.purpose}
                  </div>
                </div>

                {/* Forensic Context */}
                <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">
                    Forensic Context
                  </span>
                  <p className="text-slate-300 font-sans text-xs leading-relaxed">
                    {selectedNode.forensicContext}
                  </p>
                </div>

              </div>
            ) : (
              <div className="p-6 text-center text-slate-500 text-xs font-sans">
                Click any node on the graph canvas to inspect its forensic context.
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-[10px] text-slate-500">
            Tip: Drag nodes on the canvas to reorganize the correlation layout. Use the mouse wheel to zoom.
          </div>
        </div>

      </div>

      {/* Bottom Navigation Row */}
      <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
        <button
          type="button"
          onClick={() => onViewChange('geo-asn')}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[#08101e] hover:bg-[#0c1830] border border-slate-700 text-slate-300 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to GeoLocation & ASN</span>
        </button>

        <button
          type="button"
          onClick={() => onViewChange('investigation-case')}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
        >
          <span>Proceed to Investigation Case</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
};
