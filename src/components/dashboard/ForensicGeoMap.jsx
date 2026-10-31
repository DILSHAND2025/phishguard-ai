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
import { classifyIP, IP_CLASSIFICATION } from '../../services/emailParser.js';

// Custom SVG Pin Maker for Leaflet
function createSvgIcon(role = 'SOURCE', isDemo = false) {
  let color = '#ef4444'; // Red for SOURCE
  let fill = '#dc2626';
  if (role === 'URL_HOST') {
    color = '#f97316'; // Orange for URL Phishing
    fill = '#ea580c';
  } else if (role === 'MAIL_SERVER') {
    color = '#0284c7'; // Blue for Mail Relays
    fill = '#0369a1';
  } else if (role === 'BODY_MENTION') {
    color = '#7c3aed'; // Purple for body mentions
    fill = '#6d28d9';
  }

  const svgHtml = `
    <div style="position: relative; width: 28px; height: 34px; display: flex; align-items: center; justify-content: center;">
      <svg viewBox="0 0 24 30" width="28" height="34" style="filter: drop-shadow(0 2px 4px rgba(0,0,0,0.25));">
        <path d="M12 0C5.373 0 0 5.373 0 12c0 8.5 12 18 12 18s12-9.5 12-18c0-6.627-5.373-12-12-12z" fill="${fill}" stroke="${color}" stroke-width="1.5"/>
        <circle cx="12" cy="11" r="4.5" fill="#ffffff" />
        ${isDemo ? '<circle cx="12" cy="11" r="2" fill="#f59e0b" />' : ''}
      </svg>
    </div>
  `;

  return L.divIcon({
    html: svgHtml,
    className: 'custom-maverick-pin',
    iconSize: [28, 34],
    iconAnchor: [14, 34],
    popupAnchor: [0, -30]
  });
}

export const ForensicGeoMap = ({ 
  geoRecords = [], 
  title = "Network Intelligence",
  subtitle = "Geospatial routing and autonomous system infrastructure mapping",
  className = "",
  onSelectIP
}) => {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markersLayerRef = useRef(null);
  const [selectedIP, setSelectedIP] = useState(null);

  // Prepare display records directly from email forensic telemetry (never inject user client IP)
  const displayRecords = React.useMemo(() => {
    const raw = Array.isArray(geoRecords) ? geoRecords : (geoRecords ? [geoRecords] : []);
    return raw.filter(Boolean).map(r => {
      const rawLat = r.latitude ?? r.lat;
      const rawLng = r.longitude ?? r.lon ?? r.lng;
      const lat = typeof rawLat === 'number' ? rawLat : (rawLat !== null && rawLat !== undefined && rawLat !== '' ? parseFloat(rawLat) : null);
      const lng = typeof rawLng === 'number' ? rawLng : (rawLng !== null && rawLng !== undefined && rawLng !== '' ? parseFloat(rawLng) : null);
      const hasValidCoords = lat !== null && lng !== null && !isNaN(lat) && !isNaN(lng) && isFinite(lat) && isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
      return {
        ...r,
        latitude: hasValidCoords ? lat : (r.latitude ?? null),
        longitude: hasValidCoords ? lng : (r.longitude ?? null)
      };
    });
  }, [geoRecords]);

  // Filter records that have valid numeric coordinates within valid geographic bounds [-90, 90] & [-180, 180]
  const geolocatedPoints = React.useMemo(() => {
    return displayRecords.filter(
      r => r && 
           typeof r.latitude === 'number' && 
           typeof r.longitude === 'number' && 
           !isNaN(r.latitude) && 
           !isNaN(r.longitude) &&
           isFinite(r.latitude) &&
           isFinite(r.longitude) &&
           r.latitude >= -90 && r.latitude <= 90 &&
           r.longitude >= -180 && r.longitude <= 180
    );
  }, [displayRecords]);

  // Initialize and update Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Create map instance if not already initialized
    if (!mapInstanceRef.current) {
      if (mapContainerRef.current._leaflet_id) {
        try {
          if (mapInstanceRef.current) {
            mapInstanceRef.current.remove();
            mapInstanceRef.current = null;
          }
        } catch {
          // ignore
        }
        delete mapContainerRef.current._leaflet_id;
      }
      try {
        const map = L.map(mapContainerRef.current, {
          center: [20, 0],
          zoom: 2,
          minZoom: 1,
          maxZoom: 16,
          attributionControl: true,
          scrollWheelZoom: false
        });

        // Standard Free OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
          maxZoom: 19
        }).addTo(map);

        markersLayerRef.current = L.featureGroup().addTo(map);
        mapInstanceRef.current = map;
      } catch (err) {
        console.warn('[ForensicGeoMap] Leaflet map initialization safely caught:', err);
      }
    }

    const map = mapInstanceRef.current;
    const markersLayer = markersLayerRef.current;

    if (!map || !markersLayer) return;

    try {
      // Clear previous markers
      markersLayer.clearLayers();

      // Add markers for all resolved points
      if (geolocatedPoints.length > 0) {
        const bounds = L.latLngBounds([]);

        geolocatedPoints.forEach(record => {
          if (!record || typeof record.latitude !== 'number' || typeof record.longitude !== 'number' || isNaN(record.latitude) || isNaN(record.longitude)) {
            return;
          }
          const latLng = [record.latitude, record.longitude];
          bounds.extend(latLng);

          const icon = createSvgIcon(record.role, record.isDemo);
          const marker = L.marker(latLng, { icon });

          const safeLat = Number(record.latitude).toFixed(4);
          const safeLng = Number(record.longitude).toFixed(4);

          // Build structured popup - clean card style with evidence provenance
          const popupContent = `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 11px; line-height: 1.4; color: #1e293b; min-width: 210px; padding: 4px;">
              <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-bottom: 6px;">
                <strong style="color: #0f172a; font-size: 12px; font-family: monospace;">${record.ip || 'Unknown IP'}</strong>
                <span style="font-size: 9px; padding: 2px 6px; border-radius: 4px; background: #f1f5f9; border: 1px solid #cbd5e1; color: #475569; font-weight: 700;">
                  ${record.role || 'PUBLIC IP'}
                </span>
              </div>
              
              <div style="margin-bottom: 3px;">
                <span style="color: #64748b; font-size: 9px; text-transform: uppercase; font-weight: 600;">Location:</span>
                <div style="color: #0f172a; font-weight: 600;">${record.city ? `${record.city}, ` : ''}${record.country || 'Unknown'} ${record.countryCode ? `(${record.countryCode})` : ''}</div>
              </div>

              <div style="margin-bottom: 3px;">
                <span style="color: #64748b; font-size: 9px; text-transform: uppercase; font-weight: 600;">ISP / ASN:</span>
                <div style="color: #475569;">${record.asn || 'N/A'} • ${record.isp || record.asnOrg || 'Unknown'}</div>
              </div>

              <div style="margin-bottom: 3px;">
                <span style="color: #64748b; font-size: 9px; text-transform: uppercase; font-weight: 600;">Header Source:</span>
                <div style="color: #475569; font-size: 10px;">${record.sourceHeader || 'Email Header'}</div>
              </div>

              <div style="margin-bottom: 4px;">
                <span style="color: #64748b; font-size: 9px; text-transform: uppercase; font-weight: 600;">Coordinates:</span>
                <div style="color: #64748b; font-size: 10px; font-family: monospace;">${safeLat}, ${safeLng}</div>
              </div>

              <div style="padding-top: 4px; border-top: 1px solid #e2e8f0; margin-top: 4px; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 9px; font-weight: 600; color: ${record.isDemo ? '#d97706' : '#059669'};">
                  ${record.isDemo ? 'DEMO / TEST DATA' : (record.dataSource || 'LIVE TELEMETRY')}
                </span>
                <span style="font-size: 8px; color: #94a3b8;">${record.provider || 'Provider'}</span>
              </div>
            </div>
          `;

          marker.bindPopup(popupContent);

          marker.on('click', () => {
            setSelectedIP(record.ip);
            if (typeof onSelectIP === 'function') {
              onSelectIP(record.ip);
            }
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
        try {
          map.invalidateSize();
        } catch {
          // ignore
        }
      }, 200);

      return () => clearTimeout(timer);
    } catch (err) {
      console.warn('[ForensicGeoMap] Error updating Leaflet map layers:', err);
    }
  }, [geolocatedPoints, onSelectIP]);

  // Clean up on component unmount
  useEffect(() => {
    const container = mapContainerRef.current;
    return () => {
      if (mapInstanceRef.current) {
        try {
          mapInstanceRef.current.remove();
        } catch {
          // ignore
        }
        mapInstanceRef.current = null;
      }
      if (container && container._leaflet_id) {
        delete container._leaflet_id;
      }
    };
  }, []);

  // Handle clicking a row in the IP ledger table
  const handleFocusIP = (record) => {
    setSelectedIP(record.ip);
    if (typeof onSelectIP === 'function') {
      onSelectIP(record.ip);
    }
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

  const activeRecord = displayRecords.find(r => r.ip === selectedIP) || geolocatedPoints[0] || displayRecords[0] || null;

  return (
    <div className={`rounded-xl bg-white border border-slate-200 p-5 shadow-xs font-sans text-xs space-y-4 ${className}`}>
      
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-slate-100 text-slate-700">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-900 tracking-wide">
                {title}
              </h2>
              <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-semibold border border-slate-200">
                {geolocatedPoints.length} Resolved Node{geolocatedPoints.length === 1 ? '' : 's'}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              {subtitle}
            </p>
          </div>
        </div>

        {/* Legend / Status Badges */}
        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-600">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500"></span> Source IP
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-orange-500"></span> URL Host
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-sky-500"></span> Mail Relay
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-500"></span> Test-Net
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-slate-400"></span> Private / Local
          </span>
        </div>
      </div>

      {/* Main Grid: Interactive Map + IP Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        
        {/* Left/Main: Interactive Leaflet Map Container */}
        <div className="lg:col-span-8 flex flex-col space-y-2">
          <div className="relative w-full h-[340px] sm:h-[380px] rounded-lg overflow-hidden border border-slate-200 bg-slate-100 isolate">
            <div ref={mapContainerRef} className="w-full h-full z-0" />

            {/* If no valid coordinates exist */}
            {geolocatedPoints.length === 0 && (
              <div className="absolute inset-0 bg-white/80 backdrop-blur-2xs flex flex-col items-center justify-center p-6 text-center z-10">
                <AlertTriangle className="w-8 h-8 text-amber-500 mb-2" />
                <h3 className="text-xs font-bold text-slate-900">Geolocation Unavailable</h3>
                <p className="text-[11px] text-slate-500 max-w-sm mt-1">
                  The analyzed email indicators do not contain routable public IP addresses, or the geolocation service returned no physical coordinates.
                </p>
              </div>
            )}

            {/* Map Overlay Badge */}
            <div className="absolute top-2.5 right-2.5 z-[400] bg-white/95 border border-slate-200 px-2.5 py-1 rounded text-[10px] text-slate-700 shadow-2xs font-medium">
              Click marker for telemetry
            </div>
          </div>

          {/* Legal Forensic Attribution Standard Notice */}
          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-500 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" />
            <p className="leading-tight">
              <strong className="text-slate-800">Evidence Preservation Standard:</strong> {GEO_LEGAL_DISCLAIMER}
            </p>
          </div>
        </div>

        {/* Right: Network Indicators Ledger Table */}
        <div className="lg:col-span-4 flex flex-col space-y-2">
          <div className="rounded-lg bg-slate-50 border border-slate-200 p-3 flex-1 flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2 mb-2">
              <span className="text-[11px] uppercase font-bold text-slate-600 tracking-wider flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-slate-500" />
                IP Ledger
              </span>
              <span className="text-[10px] text-slate-400 font-medium">
                {displayRecords.length} Indicator{displayRecords.length === 1 ? '' : 's'}
              </span>
            </div>

            {/* Scrollable Indicator List */}
            <div className="space-y-2 overflow-y-auto max-h-[300px] pr-1">
              {displayRecords.length === 0 ? (
                <div className="p-4 text-center text-slate-400 text-xs">
                  No network IP indicators extracted.
                </div>
              ) : (
                displayRecords.map((rec, idx) => {
                  const isSelected = rec.ip === selectedIP;
                  const hasCoords = typeof rec.latitude === 'number' && typeof rec.longitude === 'number';

                  const effectiveClassification = rec.classification || (rec.ip ? classifyIP(rec.ip) : '');
                  const isTestNet = rec.role === 'RESERVED / TEST-NET' || effectiveClassification === IP_CLASSIFICATION.TEST_NET_IP || effectiveClassification?.includes('TEST-NET');
                  const isLoopback = rec.role === 'LOOPBACK' || effectiveClassification === IP_CLASSIFICATION.LOOPBACK_IP || effectiveClassification?.includes('Loopback');
                  const isLinkLocal = rec.role === 'LINK_LOCAL' || effectiveClassification === IP_CLASSIFICATION.LINK_LOCAL_IP || effectiveClassification?.includes('Link-local');
                  const isCGNAT = rec.role === 'CGNAT' || effectiveClassification === IP_CLASSIFICATION.CGNAT || effectiveClassification?.includes('Carrier-Grade NAT');
                  const isMulticast = rec.role === 'MULTICAST' || effectiveClassification === IP_CLASSIFICATION.MULTICAST || effectiveClassification?.includes('Multicast');
                  const isReserved = rec.role === 'RESERVED' || effectiveClassification === IP_CLASSIFICATION.RESERVED_IP || effectiveClassification?.includes('Reserved');
                  const isPrivate = rec.role === 'PRIVATE' || effectiveClassification === IP_CLASSIFICATION.PRIVATE_IP || effectiveClassification?.includes('Private');

                  const badgeText = isTestNet
                    ? 'RESERVED / TEST-NET'
                    : isLoopback
                      ? 'LOOPBACK'
                      : isLinkLocal
                        ? 'LINK_LOCAL'
                        : isCGNAT
                          ? 'CGNAT'
                          : isMulticast
                            ? 'MULTICAST'
                            : isReserved
                              ? 'RESERVED'
                              : isPrivate
                                ? 'PRIVATE'
                                : (rec.role || 'IP');

                  const badgeColor = isTestNet
                    ? 'bg-amber-50 text-amber-800 border border-amber-300'
                    : isLoopback
                      ? 'bg-purple-50 text-purple-700 border border-purple-200'
                      : isLinkLocal
                        ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                        : isCGNAT
                          ? 'bg-cyan-50 text-cyan-800 border border-cyan-300'
                          : isMulticast
                            ? 'bg-pink-50 text-pink-800 border border-pink-300'
                            : isReserved
                              ? 'bg-yellow-50 text-yellow-800 border border-yellow-300'
                              : isPrivate
                                ? 'bg-slate-100 text-slate-600 border border-slate-200'
                                : rec.role === 'SOURCE'
                                  ? 'bg-red-50 text-red-700 border border-red-200'
                                  : rec.role === 'URL_HOST'
                                    ? 'bg-orange-50 text-orange-700 border border-orange-200'
                                    : 'bg-sky-50 text-sky-700 border border-sky-200';

                  return (
                    <div
                      key={idx}
                      onClick={() => handleFocusIP(rec)}
                      className={`p-2.5 rounded-lg border transition-all cursor-pointer ${
                        isSelected 
                          ? 'bg-white border-slate-400 shadow-2xs' 
                          : 'bg-white hover:bg-slate-100/60 border-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <div className="flex items-center gap-1.5 truncate">
                          <span className="font-mono font-bold text-slate-900 text-xs truncate">
                            {rec.ip}
                          </span>
                          {rec.ipVersion && (
                            <span className="text-[9px] px-1 py-0.2 rounded bg-slate-100 text-slate-500 font-mono font-semibold">
                              {rec.ipVersion}
                            </span>
                          )}
                        </div>
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${badgeColor}`}>
                          {badgeText}
                        </span>
                      </div>

                      <div className="text-[11px] text-slate-600 flex items-center justify-between">
                        <span className="flex items-center gap-1 truncate">
                          <MapPin className="w-3 h-3 text-slate-400 shrink-0" />
                          {rec.city ? `${rec.city}, ` : ''}{rec.country || 'Unresolved'}
                        </span>
                        <span className="text-[10px] text-purple-700 font-semibold shrink-0 ml-1">
                          {rec.asn || ''}
                        </span>
                      </div>

                      <div className="text-[10px] text-slate-500 truncate mt-0.5">
                        {rec.classification ? `${rec.classification} • ` : ''}ISP: {rec.isp || rec.asnOrg || 'Unknown'}
                      </div>

                      {rec.sourceHeader && (
                        <div className="text-[9px] text-slate-400 truncate mt-0.5">
                          Source: {rec.sourceHeader}
                        </div>
                      )}

                      {/* Source attribution tag */}
                      {(() => {
                        const displayStatus = rec.isDemo 
                          ? 'DEMO DATA' 
                          : hasCoords 
                            ? 'LIVE TELEMETRY' 
                            : isTestNet 
                              ? 'RESERVED / TEST-NET' 
                              : isLoopback 
                                ? 'LOOPBACK' 
                                : isLinkLocal 
                                  ? 'LINK_LOCAL' 
                                  : isCGNAT 
                                    ? 'CGNAT' 
                                    : isMulticast 
                                      ? 'MULTICAST' 
                                      : isReserved 
                                        ? 'RESERVED' 
                                        : isPrivate 
                                          ? 'PRIVATE_IP' 
                                          : (rec.status === 'RESERVED_TEST_NET' ? 'RESERVED / TEST-NET' : (rec.status || 'UNRESOLVED'));

                        const statusColor = rec.isDemo
                          ? 'text-amber-600 font-medium'
                          : hasCoords
                            ? 'text-emerald-600 font-medium'
                            : isTestNet
                              ? 'text-amber-700 font-medium'
                              : 'text-slate-500 font-medium';

                        return (
                          <div className="flex items-center justify-between mt-1 pt-1 border-t border-slate-100 text-[9px]">
                            <span className={statusColor}>
                              {displayStatus}
                            </span>
                            {hasCoords && (
                              <span className="text-slate-600 hover:text-slate-900 hover:underline flex items-center gap-0.5 font-medium">
                                <Crosshair className="w-2.5 h-2.5" /> Focus
                              </span>
                            )}
                          </div>
                        );
                      })()}
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
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-100">
          
          {/* Observed Evidence Panel */}
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-700 tracking-wider flex items-center gap-1.5">
              <Eye className="w-3.5 h-3.5 text-slate-500" />
              Observed Evidence (Empirical Finding)
            </span>
            <p className="text-slate-700 text-xs leading-relaxed">
              {activeRecord.observedEvidence || `Observed network IP ${activeRecord.ip} routed through ${activeRecord.country || 'unresolved infrastructure'} (${activeRecord.asn || 'N/A'}).`}
            </p>
          </div>

          {/* Inferred Context Panel */}
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <span className="text-[10px] uppercase font-bold text-slate-700 tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-500" />
              Inferred Context (Threat Evaluation)
            </span>
            <p className="text-slate-700 text-xs leading-relaxed">
              {activeRecord.inferredContext || 'Network routing evaluated against known evasion proxies and anonymizing infrastructure.'}
            </p>
          </div>

        </div>
      )}

    </div>
  );
};
