import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { 
  Globe, 
  Server, 
  MapPin, 
  ShieldAlert, 
  Info, 
  AlertTriangle, 
  Eye,
  Crosshair
} from 'lucide-react';
import { GEO_LEGAL_DISCLAIMER } from '../../services/geoLocationService.js';

// Custom SVG Pin Maker for Leaflet
function createSvgIcon(role = 'SOURCE', isDemo = false) {
  let color = '#ef4444'; // Red for SOURCE
  let fill = '#991b1b';
  if (role === 'URL_HOST') {
    color = '#f97316'; // Orange for URL Phishing
    fill = '#9a3412';
  } else if (role === 'MAIL_SERVER') {
    color = '#06b6d4'; // Cyan for Mail Relays
    fill = '#0e7490';
  } else if (role === 'BODY_MENTION') {
    color = '#a855f7'; // Purple for body mentions
    fill = '#6b21a8';
  }

  const svgHtml = `
    <div style="position: relative; width: 30px; height: 36px; display: flex; align-items: center; justify-content: center;">
      <svg viewBox="0 0 24 30" width="30" height="36" style="filter: drop-shadow(0 2px 5px rgba(0,0,0,0.6));">
        <path d="M12 0C5.373 0 0 5.373 0 12c0 8.5 12 18 12 18s12-9.5 12-18c0-6.627-5.373-12-12-12z" fill="${fill}" stroke="${color}" stroke-width="2"/>
        <circle cx="12" cy="11" r="4.5" fill="#ffffff" />
        ${isDemo ? '<circle cx="12" cy="11" r="2" fill="#f59e0b" />' : ''}
      </svg>
    </div>
  `;

  return L.divIcon({
    html: svgHtml,
    className: 'custom-maverick-pin',
    iconSize: [30, 36],
    iconAnchor: [15, 36],
    popupAnchor: [0, -32]
  });
}

export const ForensicGeoMap = ({ 
  geoRecords = [], 
  title = "FORENSIC GEOLOCATION",
  subtitle = "Network Egress & Transit Infrastructure Mapping",
  className = ""
}) => {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markersLayerRef = useRef(null);
  const [selectedIP, setSelectedIP] = useState(null);

  // Filter records that have valid numeric coordinates
  const geolocatedPoints = (Array.isArray(geoRecords) ? geoRecords : []).filter(
    r => r && typeof r.latitude === 'number' && typeof r.longitude === 'number' && !isNaN(r.latitude) && !isNaN(r.longitude)
  );

  // Initialize and update Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Create map instance if not already initialized
    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current, {
        center: [20, 0],
        zoom: 2,
        minZoom: 1,
        maxZoom: 16,
        attributionControl: true,
        scrollWheelZoom: false
      });

      // CartoDB Dark Matter tiles (dark SOC aesthetic)
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
      }).addTo(map);

      markersLayerRef.current = L.featureGroup().addTo(map);
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;
    const markersLayer = markersLayerRef.current;

    // Clear previous markers
    markersLayer.clearLayers();

    // Add markers for all resolved points
    if (geolocatedPoints.length > 0) {
      const bounds = L.latLngBounds([]);

      geolocatedPoints.forEach(record => {
        const latLng = [record.latitude, record.longitude];
        bounds.extend(latLng);

        const icon = createSvgIcon(record.role, record.isDemo);
        const marker = L.marker(latLng, { icon });

        // Build structured popup
        const popupContent = `
          <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; line-height: 1.4; color: #e2e8f0; min-width: 220px; padding: 4px;">
            <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 4px; margin-bottom: 6px;">
              <strong style="color: #38bdf8; font-size: 12px;">${record.ip}</strong>
              <span style="font-size: 9px; padding: 2px 5px; border-radius: 4px; background: #0f172a; border: 1px solid #475569; color: #94a3b8; font-weight: bold;">
                ${record.role || 'PUBLIC IP'}
              </span>
            </div>
            
            <div style="margin-bottom: 3px;">
              <span style="color: #64748b; font-size: 9px; text-transform: uppercase;">Location:</span>
              <div style="color: #f1f5f9; font-weight: 600;">${record.city ? `${record.city}, ` : ''}${record.country || 'Unknown'} ${record.countryCode ? `(${record.countryCode})` : ''}</div>
            </div>

            <div style="margin-bottom: 3px;">
              <span style="color: #64748b; font-size: 9px; text-transform: uppercase;">ISP / ASN:</span>
              <div style="color: #c084fc;">${record.asn || 'N/A'} • ${record.isp || record.asnOrg || 'Unknown'}</div>
            </div>

            <div style="margin-bottom: 4px;">
              <span style="color: #64748b; font-size: 9px; text-transform: uppercase;">Coordinates:</span>
              <div style="color: #94a3b8; font-size: 10px;">${record.latitude.toFixed(4)}, ${record.longitude.toFixed(4)} ${record.timezone ? `(${record.timezone})` : ''}</div>
            </div>

            <div style="padding-top: 4px; border-top: 1px solid #1e293b; margin-top: 4px;">
              <span style="font-size: 9px; font-weight: bold; color: ${record.isDemo ? '#f59e0b' : '#34d399'};">
                ${record.dataSource || 'FORENSIC TELEMETRY'}
              </span>
            </div>
          </div>
        `;

        marker.bindPopup(popupContent, {
          className: 'maverick-dark-popup'
        });

        marker.on('click', () => {
          setSelectedIP(record.ip);
        });

        markersLayer.addLayer(marker);
      });

      // Fit map viewport to include all markers
      if (geolocatedPoints.length === 1) {
        map.setView([geolocatedPoints[0].latitude, geolocatedPoints[0].longitude], 5);
      } else {
        map.fitBounds(bounds, { padding: [30, 30], maxZoom: 8 });
      }
    } else {
      map.setView([20, 0], 2);
    }

    // Leaflet container resize check
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);

    return () => clearTimeout(timer);
  }, [geolocatedPoints]);

  // Clean up on component unmount
  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Handle clicking a row in the IP ledger table
  const handleFocusIP = (record) => {
    setSelectedIP(record.ip);
    if (mapInstanceRef.current && typeof record.latitude === 'number' && typeof record.longitude === 'number') {
      mapInstanceRef.current.setView([record.latitude, record.longitude], 7, { animate: true });
      if (markersLayerRef.current) {
        markersLayerRef.current.eachLayer(layer => {
          const latLng = layer.getLatLng();
          if (Math.abs(latLng.lat - record.latitude) < 0.0001 && Math.abs(latLng.lng - record.longitude) < 0.0001) {
            layer.openPopup();
          }
        });
      }
    }
  };

  const activeRecord = geoRecords.find(r => r.ip === selectedIP) || geolocatedPoints[0] || geoRecords[0] || null;

  return (
    <div className={`rounded-xl bg-[#09101e] border border-cyan-500/40 p-5 shadow-[0_0_25px_rgba(6,182,212,0.12)] font-mono text-xs space-y-4 ${className}`}>
      
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-extrabold text-white tracking-wider flex items-center gap-2">
                <span>{title}</span>
              </h2>
              <span className="px-2 py-0.5 rounded bg-blue-950/80 border border-blue-500/40 text-blue-300 text-[10px] font-bold">
                {geolocatedPoints.length} Resolved Node{geolocatedPoints.length === 1 ? '' : 's'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {subtitle}
            </p>
          </div>
        </div>

        {/* Legend / Status Badges */}
        <div className="flex flex-wrap items-center gap-2 text-[10px]">
          <span className="flex items-center gap-1 text-red-400">
            <span className="w-2 h-2 rounded-full bg-red-500"></span> Source IP
          </span>
          <span className="flex items-center gap-1 text-orange-400">
            <span className="w-2 h-2 rounded-full bg-orange-500"></span> URL Infrastructure
          </span>
          <span className="flex items-center gap-1 text-cyan-400">
            <span className="w-2 h-2 rounded-full bg-cyan-500"></span> Mail Relay
          </span>
        </div>
      </div>

      {/* Main Grid: Interactive Map + IP Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        
        {/* Left/Main: Interactive Leaflet Map Container */}
        <div className="lg:col-span-8 flex flex-col space-y-2">
          <div className="relative w-full h-[340px] sm:h-[380px] rounded-lg overflow-hidden border border-slate-800 bg-[#050912]">
            <div ref={mapContainerRef} className="w-full h-full z-0" />

            {/* If no valid coordinates exist */}
            {geolocatedPoints.length === 0 && (
              <div className="absolute inset-0 bg-[#070b14]/80 backdrop-blur-xs flex flex-col items-center justify-center p-6 text-center z-10">
                <AlertTriangle className="w-8 h-8 text-amber-400 mb-2" />
                <h3 className="text-xs font-bold text-white">Geolocation Unavailable</h3>
                <p className="text-[11px] text-slate-400 max-w-sm mt-1">
                  The analyzed email indicators do not contain routable public IP addresses, or the geolocation service returned no physical coordinates.
                </p>
              </div>
            )}

            {/* Map Overlay Badge */}
            <div className="absolute top-2.5 right-2.5 z-[400] bg-[#070b14]/90 border border-slate-700/80 px-2.5 py-1 rounded text-[10px] text-slate-300 backdrop-blur-xs shadow-md">
              <span className="text-cyan-400 font-semibold">Interactive Mode:</span> Click marker for telemetry
            </div>
          </div>

          {/* Legal Forensic Attribution Standard Notice */}
          <div className="p-2 rounded bg-[#060a14] border border-slate-800/80 text-[10px] text-slate-400 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
            <p className="leading-tight">
              <strong className="text-slate-300">CERT-In Admissibility Standard:</strong> {GEO_LEGAL_DISCLAIMER}
            </p>
          </div>
        </div>

        {/* Right: Network Indicators Ledger Table */}
        <div className="lg:col-span-4 flex flex-col space-y-2">
          <div className="rounded-lg bg-[#060a14] border border-slate-800 p-3 flex-1 flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2 mb-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                Network Indicators Ledger
              </span>
              <span className="text-[10px] text-slate-500">
                {geoRecords.length} Indicator{geoRecords.length === 1 ? '' : 's'}
              </span>
            </div>

            {/* Scrollable Indicator List */}
            <div className="space-y-2 overflow-y-auto max-h-[300px] pr-1">
              {geoRecords.length === 0 ? (
                <div className="p-4 text-center text-slate-500 text-[11px]">
                  No network IP indicators extracted.
                </div>
              ) : (
                geoRecords.map((rec, idx) => {
                  const isSelected = rec.ip === selectedIP;
                  const hasCoords = typeof rec.latitude === 'number' && typeof rec.longitude === 'number';

                  return (
                    <div
                      key={idx}
                      onClick={() => handleFocusIP(rec)}
                      className={`p-2.5 rounded-lg border transition-all cursor-pointer ${
                        isSelected 
                          ? 'bg-cyan-950/30 border-cyan-500/60 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                          : 'bg-[#09101e] hover:bg-[#0d162a] border-slate-800/80'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-bold text-cyan-300 text-xs truncate">
                          {rec.ip}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                          rec.role === 'SOURCE' 
                            ? 'bg-red-950 text-red-300 border border-red-500/40'
                            : rec.role === 'URL_HOST'
                              ? 'bg-orange-950 text-orange-300 border border-orange-500/40'
                              : rec.isPrivate
                                ? 'bg-slate-800 text-slate-400 border border-slate-700'
                                : 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
                        }`}>
                          {rec.role || 'IP'}
                        </span>
                      </div>

                      <div className="text-[10.5px] text-slate-300 flex items-center justify-between">
                        <span className="flex items-center gap-1 truncate">
                          <MapPin className="w-3 h-3 text-blue-400 shrink-0" />
                          {rec.city ? `${rec.city}, ` : ''}{rec.country || 'Unresolved'}
                        </span>
                        <span className="text-[10px] text-purple-300 font-semibold shrink-0 ml-1">
                          {rec.asn || ''}
                        </span>
                      </div>

                      <div className="text-[10px] text-slate-500 truncate mt-0.5">
                        ISP: {rec.isp || rec.asnOrg || 'Unknown'}
                      </div>

                      {/* Source attribution tag */}
                      <div className="flex items-center justify-between mt-1 pt-1 border-t border-slate-800/60 text-[9px]">
                        <span className={rec.isDemo ? 'text-amber-400 font-semibold' : 'text-emerald-400'}>
                          {rec.isDemo ? 'DEMO / SYNTHETIC DATA' : hasCoords ? 'LIVE TELEMETRY' : rec.status}
                        </span>
                        {hasCoords && (
                          <span className="text-cyan-400 hover:underline flex items-center gap-0.5">
                            <Crosshair className="w-2.5 h-2.5" /> Locate
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

      </div>

      {/* Forensic Evidence Breakdown: Observed vs Inferred */}
      {activeRecord && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800">
          
          {/* Observed Evidence Panel */}
          <div className="p-3 rounded-lg bg-[#060a14] border border-blue-500/30 space-y-1">
            <span className="text-[10px] uppercase font-bold text-blue-400 tracking-wider flex items-center gap-1.5">
              <Eye className="w-3.5 h-3.5" />
              Observed Evidence (Empirical Finding)
            </span>
            <p className="text-slate-200 text-[11px] leading-relaxed">
              {activeRecord.observedEvidence || `Observed network IP ${activeRecord.ip} routed through ${activeRecord.country || 'unresolved infrastructure'} (${activeRecord.asn || 'N/A'}).`}
            </p>
          </div>

          {/* Inferred Context Panel */}
          <div className="p-3 rounded-lg bg-[#060a14] border border-amber-500/30 space-y-1">
            <span className="text-[10px] uppercase font-bold text-amber-400 tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" />
              Inferred Information (Contextual Threat Evaluation)
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              {activeRecord.inferredContext || 'Network routing evaluated against known evasion proxies and anonymizing infrastructure.'}
            </p>
          </div>

        </div>
      )}

    </div>
  );
};
